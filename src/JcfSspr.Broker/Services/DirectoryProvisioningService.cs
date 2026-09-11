using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net.Mail;
using System.Text;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class DirectoryProvisioningService(
    SecurityDbContext db,
    IOptions<DirectoryOptions> directoryOptions,
    IOptions<ProvisioningOptions> provisioningOptions,
    ProvisioningPolicyService policies,
    TimeProvider timeProvider)
{
    private readonly DirectoryOptions _directory = directoryOptions.Value;
    private readonly ProvisioningOptions _provisioning = provisioningOptions.Value;

    public async Task<DirectoryResolution> ResolveOrProvisionAsync(HrPersonRecord person, string requestedProfileCode, CancellationToken cancellationToken)
    {
        var existingLink = await db.SubjectIdentities.SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, cancellationToken);
        using var connection = OpenConnection();
        if (existingLink?.AdObjectGuid is Guid linkedGuid)
        {
            var linked = FindByGuid(connection, linkedGuid);
            if (linked is not null && Attribute(linked, "employeeID").Equals(person.SubjectId, StringComparison.OrdinalIgnoreCase))
                return new DirectoryResolution(ToMember(person, linked), false, false, existingLink.ProvisioningState);
            await CreateReviewAsync(person.SubjectId, "BrokenAuthoritativeLink", "Stored AD ObjectGUID no longer resolves to the same employeeID.", cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }

        var candidates = FindCandidates(connection, person);
        var exact = candidates.Where(x => Attribute(x, "employeeID").Equals(person.SubjectId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (exact.Length == 1 && candidates.Count == 1)
        {
            var member = ToMember(person, exact[0]);
            await SaveLinkAsync(person, member, "Existing", string.Empty, cancellationToken);
            return new DirectoryResolution(member, false, false, "Existing");
        }
        if (candidates.Count > 0)
        {
            await CreateReviewAsync(person.SubjectId, "DirectoryIdentityConflict", "One or more directory objects matched employee attributes but could not be uniquely bound to the HR employee ID.", cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }
        if (!_provisioning.AutoCreateEnabled)
        {
            await CreateReviewAsync(person.SubjectId, "AutoProvisioningDisabled", "No AD account exists and automatic provisioning is disabled.", cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }

        ProvisioningProfileOptions profile;
        try { profile = policies.GetForSelfService(requestedProfileCode); }
        catch (InvalidOperationException ex)
        {
            await CreateReviewAsync(person.SubjectId, "InvalidProvisioningProfile", ex.Message, cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }

        var account = BuildAccountName(person.EmailAddress);
        if (string.IsNullOrWhiteSpace(account))
        {
            await CreateReviewAsync(person.SubjectId, "MissingUsableEmail", "HR does not contain an email address that can safely derive the directory account name.", cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }
        var upn = BuildUpn(account);
        if (FindByAccountName(connection, account, upn) is not null)
        {
            await CreateReviewAsync(person.SubjectId, "AccountNameCollision", "The proposed sAMAccountName or UPN already exists for another directory object.", cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }

        SearchResultEntry created;
        try
        {
            created = CreateDisabledAccount(connection, person, account, upn, profile);
            AddBaselineGroups(connection, created.DistinguishedName, profile);
        }
        catch (DirectoryOperationException ex)
        {
            await CreateReviewAsync(person.SubjectId, "ProvisioningOperationFailed", SanitizeDirectoryError(ex.Message), cancellationToken);
            return DirectoryResolution.ReviewRequired;
        }

        var memberRecord = ToMember(person, created);
        await SaveLinkAsync(person, memberRecord, "CreatedDisabled", profile.Code, cancellationToken);
        return new DirectoryResolution(memberRecord, true, false, "CreatedDisabled");
    }

    public async Task CompleteNewAccountAsync(string subjectId, CancellationToken cancellationToken)
    {
        var link = await db.SubjectIdentities.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (link?.AdObjectGuid is not Guid objectGuid || !link.ProvisioningState.Equals("CreatedDisabled", StringComparison.OrdinalIgnoreCase)) return;
        using var connection = OpenConnection();
        var entry = FindByGuid(connection, objectGuid) ?? throw new InvalidOperationException("Newly provisioned directory object no longer exists.");
        var current = int.TryParse(Attribute(entry, "userAccountControl"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 514;
        var enabled = current & ~2;
        var modification = new DirectoryAttributeModification { Name = "userAccountControl", Operation = DirectoryAttributeOperation.Replace };
        modification.Add(enabled.ToString(CultureInfo.InvariantCulture));
        connection.SendRequest(new ModifyRequest(entry.DistinguishedName, modification), TimeSpan.FromSeconds(_directory.TimeoutSeconds));
        link.ProvisioningState = "Active";
        link.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ApplyAdminProfileAsync(string subjectId, string profileCode, string actor, CancellationToken cancellationToken)
    {
        var link = await db.SubjectIdentities.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken)
            ?? throw new InvalidOperationException("Subject is not linked to an AD account.");
        if (link.AdObjectGuid is not Guid objectGuid) throw new InvalidOperationException("Subject has no AD object mapping.");
        var profile = policies.GetForAdmin(profileCode);
        using var connection = OpenConnection();
        var entry = FindByGuid(connection, objectGuid) ?? throw new InvalidOperationException("Linked AD account no longer exists.");
        var rdn = entry.DistinguishedName.Split(',', 2, StringSplitOptions.TrimEntries)[0];
        if (!entry.DistinguishedName.EndsWith(profile.TargetOuDn, StringComparison.OrdinalIgnoreCase))
        {
            connection.SendRequest(new ModifyDNRequest(entry.DistinguishedName, profile.TargetOuDn, rdn) { DeleteOldRdn = true }, TimeSpan.FromSeconds(_directory.TimeoutSeconds));
            entry = FindByGuid(connection, objectGuid) ?? throw new InvalidOperationException("AD account could not be resolved after OU move.");
        }
        ReconcileManagedGroups(connection, entry.DistinguishedName, profile);
        link.ProvisioningProfileCode = profile.Code;
        link.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        db.Audits.Add(new AuditEntity
        {
            Id = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = timeProvider.GetUtcNow().UtcDateTime,
            SubjectId = subjectId, ComputerNumber = link.ComputerNumber, AccountName = link.AdAccountName, Actor = actor,
            Category = "Administration", Outcome = "Success", DetailCode = "ProvisioningProfileApplied"
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    private LdapConnection OpenConnection()
    {
        var identifier = new LdapDirectoryIdentifier(_directory.Server, _directory.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        var connection = new LdapConnection(identifier) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(_directory.TimeoutSeconds) };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        connection.Bind();
        return connection;
    }

    private List<SearchResultEntry> FindCandidates(LdapConnection connection, HrPersonRecord person)
    {
        var clauses = new List<string> { $"(employeeID={EscapeFilter(person.SubjectId)})" };
        if (!string.IsNullOrWhiteSpace(person.EmailAddress))
        {
            var email = EscapeFilter(person.EmailAddress);
            clauses.Add($"(mail={email})");
            clauses.Add($"(userPrincipalName={email})");
            clauses.Add($"(proxyAddresses=smtp:{email})");
            clauses.Add($"(proxyAddresses=SMTP:{email})");
        }
        var filter = "(|" + string.Concat(clauses) + ")";
        var request = new SearchRequest(SearchBase, filter, SearchScope.Subtree, "objectGUID", "sAMAccountName", "userPrincipalName", "mail", "employeeID", "userAccountControl");
        request.TimeLimit = TimeSpan.FromSeconds(_directory.TimeoutSeconds);
        var response = (SearchResponse)connection.SendRequest(request, TimeSpan.FromSeconds(_directory.TimeoutSeconds));
        return response.Entries.Cast<SearchResultEntry>().Take(5).ToList();
    }

    private SearchResultEntry? FindByGuid(LdapConnection connection, Guid guid)
    {
        var filter = "(objectGUID=" + string.Concat(guid.ToByteArray().Select(x => $"\\{x:X2}")) + ")";
        return FindSingle(connection, filter);
    }

    private SearchResultEntry? FindByAccountName(LdapConnection connection, string account, string upn)
        => FindSingle(connection, $"(|(sAMAccountName={EscapeFilter(account)})(userPrincipalName={EscapeFilter(upn)}))");

    private SearchResultEntry? FindSingle(LdapConnection connection, string filter)
    {
        var request = new SearchRequest(SearchBase, filter, SearchScope.Subtree, "objectGUID", "sAMAccountName", "userPrincipalName", "mail", "employeeID", "userAccountControl");
        request.TimeLimit = TimeSpan.FromSeconds(_directory.TimeoutSeconds);
        var response = (SearchResponse)connection.SendRequest(request, TimeSpan.FromSeconds(_directory.TimeoutSeconds));
        return response.Entries.Count == 1 ? response.Entries[0] : null;
    }

    private SearchResultEntry CreateDisabledAccount(LdapConnection connection, HrPersonRecord person, string account, string upn, ProvisioningProfileOptions profile)
    {
        var cn = EscapeDnValue($"{person.DisplayName} {person.SubjectId}".Trim());
        var dn = $"CN={cn},{profile.TargetOuDn}";
        var add = new AddRequest(dn);
        add.Attributes.Add(new DirectoryAttribute("objectClass", "top", "person", "organizationalPerson", "user"));
        add.Attributes.Add(new DirectoryAttribute("cn", person.DisplayName));
        add.Attributes.Add(new DirectoryAttribute("displayName", person.DisplayName));
        add.Attributes.Add(new DirectoryAttribute("givenName", person.FirstName));
        add.Attributes.Add(new DirectoryAttribute("sn", person.LastName));
        if (!string.IsNullOrWhiteSpace(person.MiddleName)) add.Attributes.Add(new DirectoryAttribute("initials", person.MiddleName[..1]));
        add.Attributes.Add(new DirectoryAttribute("sAMAccountName", account));
        add.Attributes.Add(new DirectoryAttribute("userPrincipalName", upn));
        add.Attributes.Add(new DirectoryAttribute("mail", person.EmailAddress));
        add.Attributes.Add(new DirectoryAttribute("employeeID", person.SubjectId));
        if (!string.IsNullOrWhiteSpace(person.ComputerNumber)) add.Attributes.Add(new DirectoryAttribute("employeeNumber", person.ComputerNumber));
        add.Attributes.Add(new DirectoryAttribute("userAccountControl", "514"));
        connection.SendRequest(add, TimeSpan.FromSeconds(_directory.TimeoutSeconds));
        return FindSingle(connection, $"(employeeID={EscapeFilter(person.SubjectId)})") ?? throw new InvalidOperationException("Directory account was created but could not be resolved.");
    }

    private void AddBaselineGroups(LdapConnection connection, string userDn, ProvisioningProfileOptions profile)
    {
        foreach (var groupDn in profile.GroupDns.Distinct(StringComparer.OrdinalIgnoreCase)) AddToManagedGroup(connection, groupDn, userDn);
    }

    private void ReconcileManagedGroups(LdapConnection connection, string userDn, ProvisioningProfileOptions profile)
    {
        var desired = profile.GroupDns.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var managed = _provisioning.Profiles.SelectMany(x => x.GroupDns).Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(group => !_provisioning.BlockedGroupDns.Contains(group, StringComparer.OrdinalIgnoreCase) && !_directory.DeniedGroupDns.Contains(group, StringComparer.OrdinalIgnoreCase));
        foreach (var groupDn in managed)
        {
            if (desired.Contains(groupDn)) AddToManagedGroup(connection, groupDn, userDn);
            else RemoveFromManagedGroup(connection, groupDn, userDn);
        }
    }

    private void AddToManagedGroup(LdapConnection connection, string groupDn, string userDn)
    {
        EnsureGroupAllowed(groupDn);
        var modification = new DirectoryAttributeModification { Name = "member", Operation = DirectoryAttributeOperation.Add };
        modification.Add(userDn);
        try { connection.SendRequest(new ModifyRequest(groupDn, modification), TimeSpan.FromSeconds(_directory.TimeoutSeconds)); }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.AttributeOrValueExists) { }
    }

    private void RemoveFromManagedGroup(LdapConnection connection, string groupDn, string userDn)
    {
        EnsureGroupAllowed(groupDn);
        var modification = new DirectoryAttributeModification { Name = "member", Operation = DirectoryAttributeOperation.Delete };
        modification.Add(userDn);
        try { connection.SendRequest(new ModifyRequest(groupDn, modification), TimeSpan.FromSeconds(_directory.TimeoutSeconds)); }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchAttribute) { }
    }

    private void EnsureGroupAllowed(string groupDn)
    {
        if (_provisioning.BlockedGroupDns.Contains(groupDn, StringComparer.OrdinalIgnoreCase) || _directory.DeniedGroupDns.Contains(groupDn, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("A blocked privileged group was requested.");
    }

    private async Task SaveLinkAsync(HrPersonRecord person, MemberRecord member, string state, string profileCode, CancellationToken cancellationToken)
    {
        var entity = await db.SubjectIdentities.SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, cancellationToken);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (entity is null)
        {
            entity = new SubjectIdentityEntity { SubjectId = person.SubjectId, CreatedUtc = now };
            db.SubjectIdentities.Add(entity);
        }
        entity.ComputerNumber = person.ComputerNumber;
        entity.RegulationNumber = person.RegulationNumber;
        entity.EmailAddress = person.EmailAddress;
        entity.AdAccountName = member.AdAccountName;
        entity.AdObjectGuid = member.AdObjectGuid;
        entity.ProvisioningState = state;
        if (!string.IsNullOrWhiteSpace(profileCode)) entity.ProvisioningProfileCode = profileCode;
        entity.UpdatedUtc = now;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task CreateReviewAsync(string subjectId, string reason, string details, CancellationToken cancellationToken)
    {
        db.ProvisioningReviews.Add(new ProvisioningReviewEntity
        {
            Id = Guid.NewGuid(), SubjectId = subjectId, ReasonCode = reason, Details = details, CreatedUtc = timeProvider.GetUtcNow().UtcDateTime
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    private static MemberRecord ToMember(HrPersonRecord person, SearchResultEntry entry)
    {
        var guidBytes = entry.Attributes["objectGUID"]?[0] as byte[] ?? throw new InvalidOperationException("AD objectGUID is missing.");
        return new MemberRecord
        {
            ComputerNumber = person.ComputerNumber,
            FirstName = person.FirstName,
            LastName = person.LastName,
            Trn = person.Trn,
            DateOfBirth = person.DateOfBirth,
            AdAccountName = Attribute(entry, "sAMAccountName"),
            AdObjectGuid = new Guid(guidBytes),
            EmailAddress = person.EmailAddress
        };
    }

    private string SearchBase => string.IsNullOrWhiteSpace(_directory.ProvisioningSearchBaseDn) ? _directory.BaseDn : _directory.ProvisioningSearchBaseDn;
    private string BuildUpn(string account) => string.IsNullOrWhiteSpace(_directory.UpnSuffix) ? account : $"{account}@{_directory.UpnSuffix.TrimStart('@')}";

    private static string BuildAccountName(string email)
    {
        try
        {
            var address = new MailAddress(email);
            var local = address.User;
            var normalized = new string(local.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_').ToArray()).Trim('.', '-', '_');
            return normalized.Length > 20 ? normalized[..20] : normalized;
        }
        catch (FormatException) { return string.Empty; }
    }

    private static string Attribute(SearchResultEntry entry, string name) =>
        entry.Attributes[name] is DirectoryAttribute attribute && attribute.Count > 0
            ? Convert.ToString(attribute[0], CultureInfo.InvariantCulture)?.Trim() ?? string.Empty
            : string.Empty;

    private static string EscapeFilter(string value) => value.Replace("\\", "\\5c", StringComparison.Ordinal).Replace("*", "\\2a", StringComparison.Ordinal).Replace("(", "\\28", StringComparison.Ordinal).Replace(")", "\\29", StringComparison.Ordinal).Replace("\0", "\\00", StringComparison.Ordinal);

    private static string EscapeDnValue(string value)
    {
        if (value.Length == 0) return value;
        var builder = new StringBuilder(value.Length + 8);
        for (var i = 0; i < value.Length; i++)
        {
            var character = value[i];
            if (character == '\0') { builder.Append("\\00"); continue; }
            var escape = character is ',' or '+' or '"' or '\\' or '<' or '>' or ';' or '=' || (i == 0 && (character is ' ' or '#')) || (i == value.Length - 1 && character == ' ');
            if (escape) builder.Append('\\');
            builder.Append(character);
        }
        return builder.ToString();
    }

    private static string SanitizeDirectoryError(string value) => value.Length > 200 ? value[..200] : value;
}

public sealed record DirectoryResolution(MemberRecord? Member, bool AccountCreated, bool AdminReviewRequired, string State)
{
    public static DirectoryResolution ReviewRequired => new(null, false, true, "AdminReview");
}
