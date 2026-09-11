using System.Globalization;
using System.Text.RegularExpressions;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed partial class HrIdentityDirectoryService(IConfiguration configuration, IOptions<MemberDirectoryOptions> options)
{
    private readonly string _connectionString = configuration.GetConnectionString("MemberDirectory")
        ?? throw new InvalidOperationException("ConnectionStrings:MemberDirectory is required.");
    private readonly string _view = ValidateViewName(options.Value.ViewName);
    private readonly HashSet<string> _activeStatuses = options.Value.ActiveEmploymentStatuses.ToHashSet(StringComparer.OrdinalIgnoreCase);

    public async Task<HrPersonRecord?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken)
    {
        var normalized = identifier.Trim();
        if (normalized.Length is < 2 or > 128) return null;
        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var sql = $"SELECT TOP(3) [EmployeeId],[ComputerNumber],[RegulationNumber],[Username],[FirstName],[MiddleName],[LastName],[TRN],[DateOfBirth],[EmailAddress],[EmploymentStatus],[PhotoBase64],[PhotoContentType] FROM {_view} WHERE [EmployeeId]=@id OR [ComputerNumber]=@id OR [RegulationNumber]=@id OR [Username]=@id OR [EmailAddress]=@id";
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@id", normalized);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        HrPersonRecord? result = null;
        var count = 0;
        while (await reader.ReadAsync(cancellationToken))
        {
            count++;
            if (count == 1) result = Map(reader);
        }
        if (count > 1) throw new AmbiguousIdentityException();
        if (result is null || (_activeStatuses.Count > 0 && !_activeStatuses.Contains(result.EmploymentStatus))) return null;
        return result;
    }

    public async Task<HrPersonRecord?> FindBySubjectIdAsync(string subjectId, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var sql = $"SELECT TOP(2) [EmployeeId],[ComputerNumber],[RegulationNumber],[Username],[FirstName],[MiddleName],[LastName],[TRN],[DateOfBirth],[EmailAddress],[EmploymentStatus],[PhotoBase64],[PhotoContentType] FROM {_view} WHERE [EmployeeId]=@id";
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@id", subjectId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        HrPersonRecord? result = null;
        if (await reader.ReadAsync(cancellationToken)) result = Map(reader);
        if (await reader.ReadAsync(cancellationToken)) throw new AmbiguousIdentityException();
        if (result is null || (_activeStatuses.Count > 0 && !_activeStatuses.Contains(result.EmploymentStatus))) return null;
        return result;
    }

    public static bool Corroborates(HrPersonRecord person, string trn, DateOnly? dateOfBirth, string middleName)
    {
        var checks = 0;
        var matches = 0;
        if (!string.IsNullOrWhiteSpace(trn)) { checks++; if (SameDigits(person.Trn, trn)) matches++; }
        if (dateOfBirth.HasValue) { checks++; if (person.DateOfBirth == dateOfBirth.Value) matches++; }
        if (!string.IsNullOrWhiteSpace(middleName)) { checks++; if (SameLetters(person.MiddleName, middleName)) matches++; }
        return checks >= 2 && checks == matches;
    }

    private static HrPersonRecord Map(SqlDataReader reader)
    {
        static string Text(SqlDataReader r, string name) => Convert.ToString(r[name], CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;
        var photo = Text(reader, "PhotoBase64");
        if (photo.Length > 2_000_000) photo = string.Empty;
        return new HrPersonRecord
        {
            SubjectId = Text(reader, "EmployeeId"),
            ComputerNumber = Text(reader, "ComputerNumber"),
            RegulationNumber = Text(reader, "RegulationNumber"),
            Username = Text(reader, "Username"),
            FirstName = Text(reader, "FirstName"),
            MiddleName = Text(reader, "MiddleName"),
            LastName = Text(reader, "LastName"),
            Trn = Text(reader, "TRN"),
            DateOfBirth = DateOnly.FromDateTime(Convert.ToDateTime(reader["DateOfBirth"], CultureInfo.InvariantCulture)),
            EmailAddress = Text(reader, "EmailAddress"),
            EmploymentStatus = Text(reader, "EmploymentStatus"),
            PhotoBase64 = photo,
            PhotoContentType = Text(reader, "PhotoContentType") is { Length: > 0 } contentType ? contentType : "image/jpeg"
        };
    }

    private static bool SameLetters(string left, string right) => LettersOnly().Replace(left, string.Empty).Equals(LettersOnly().Replace(right, string.Empty), StringComparison.OrdinalIgnoreCase);
    private static bool SameDigits(string left, string right) => DigitsOnly().Replace(left, string.Empty).Equals(DigitsOnly().Replace(right, string.Empty), StringComparison.Ordinal);
    private static string ValidateViewName(string value) => SqlObjectName().IsMatch(value) ? value : throw new InvalidOperationException("MemberDirectory:ViewName contains unsupported characters.");

    [GeneratedRegex("[^\\p{L}]", RegexOptions.CultureInvariant)] private static partial Regex LettersOnly();
    [GeneratedRegex("[^0-9]", RegexOptions.CultureInvariant)] private static partial Regex DigitsOnly();
    [GeneratedRegex("^[A-Za-z0-9_\\[\\]\\.]+$", RegexOptions.CultureInvariant)] private static partial Regex SqlObjectName();
}
