using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class ProvisioningPolicyService(IOptions<ProvisioningOptions> options, TimeProvider timeProvider)
{
    private readonly ProvisioningOptions _options = options.Value;

    public ProvisioningProfileOptions GetForSelfService(string requestedCode)
    {
        var code = string.IsNullOrWhiteSpace(requestedCode) ? _options.DefaultProfileCode : requestedCode.Trim();
        var profile = ActiveProfiles().SingleOrDefault(x => x.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
        if (profile is null) throw new InvalidOperationException("No active provisioning profile matches this request.");
        if (!profile.Code.Equals(_options.DefaultProfileCode, StringComparison.OrdinalIgnoreCase) && !profile.UserSelectable)
            throw new InvalidOperationException("This provisioning profile cannot be selected by self-service users.");
        ValidateProfile(profile);
        return profile;
    }

    public ProvisioningProfileOptions GetForAdmin(string code)
    {
        var profile = ActiveProfiles().SingleOrDefault(x => x.Code.Equals(code, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("No active provisioning profile matches this request.");
        ValidateProfile(profile);
        return profile;
    }

    private IEnumerable<ProvisioningProfileOptions> ActiveProfiles()
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        return _options.Profiles.Where(x => x.Enabled && (!x.EffectiveFromUtc.HasValue || x.EffectiveFromUtc <= now) && (!x.EffectiveToUtc.HasValue || x.EffectiveToUtc > now));
    }

    private void ValidateProfile(ProvisioningProfileOptions profile)
    {
        if (!profile.TargetOuDn.StartsWith("OU=", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Provisioning profile target must be an OU DN.");
        foreach (var group in profile.GroupDns)
        {
            if (_options.BlockedGroupDns.Contains(group, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("Provisioning profile contains a blocked privileged group.");
        }
    }
}
