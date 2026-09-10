using System.Text.RegularExpressions;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Core.Contracts;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed partial class MemberDirectoryService(IConfiguration configuration, IOptions<MemberDirectoryOptions> options)
{
    private readonly string _connectionString = configuration.GetConnectionString("MemberDirectory")
        ?? throw new InvalidOperationException("ConnectionStrings:MemberDirectory is required.");
    private readonly string _view = ValidateViewName(options.Value.ViewName);

    public async Task<MemberRecord?> VerifyAsync(VerificationRequest request, CancellationToken cancellationToken)
    {
        if (!int.TryParse(request.ComputerNumber, out var number)) return null;
        var member = await FindByComputerNumberAsync(number, cancellationToken);
        if (member is null) return null;
        return SameLetters(member.FirstName, request.FirstName)
            && SameLetters(member.LastName, request.LastName)
            && SameDigits(member.Trn, request.Trn)
            && member.DateOfBirth == request.DateOfBirth
            ? member : null;
    }

    public async Task<MemberRecord?> FindByAccountNameAsync(string accountName, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var sql = $"SELECT TOP(2) [Computer No],[First Name],[Last Name],[TRN],[Date of Birth],[AD Account Name],[AD Object GUID],[Email Address] FROM {_view} WHERE [AD Account Name]=@account";
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@account", accountName);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        MemberRecord? result = null;
        if (await reader.ReadAsync(cancellationToken)) result = Map(reader);
        if (await reader.ReadAsync(cancellationToken)) throw new InvalidOperationException("Authoritative member mapping returned duplicate AD account names.");
        return result;
    }

    public async Task<MemberRecord?> FindByComputerNumberAsync(int number, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var sql = $"SELECT TOP(2) [Computer No],[First Name],[Last Name],[TRN],[Date of Birth],[AD Account Name],[AD Object GUID],[Email Address] FROM {_view} WHERE [Computer No]=@number";
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@number", number);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        MemberRecord? result = null;
        if (await reader.ReadAsync(cancellationToken)) result = Map(reader);
        if (await reader.ReadAsync(cancellationToken)) throw new InvalidOperationException("Authoritative member mapping returned duplicate computer numbers.");
        return result;
    }

    private static MemberRecord Map(SqlDataReader reader)
    {
        var guidValue = reader["AD Object GUID"];
        var guid = guidValue switch
        {
            Guid g => g,
            byte[] bytes when bytes.Length == 16 => new Guid(bytes),
            string text when Guid.TryParse(text, out var parsed) => parsed,
            _ => throw new InvalidOperationException("AD Object GUID is missing or invalid for a member record.")
        };
        return new MemberRecord
        {
            ComputerNumber = Convert.ToString(reader["Computer No"], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            FirstName = Convert.ToString(reader["First Name"], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            LastName = Convert.ToString(reader["Last Name"], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            Trn = Convert.ToString(reader["TRN"], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            DateOfBirth = DateOnly.FromDateTime(Convert.ToDateTime(reader["Date of Birth"], System.Globalization.CultureInfo.InvariantCulture)),
            AdAccountName = Convert.ToString(reader["AD Account Name"], System.Globalization.CultureInfo.InvariantCulture)?.Trim() ?? string.Empty,
            AdObjectGuid = guid,
            EmailAddress = Convert.ToString(reader["Email Address"], System.Globalization.CultureInfo.InvariantCulture)?.Trim() ?? string.Empty
        };
    }

    private static bool SameLetters(string a, string b) => LettersOnly().Replace(a, string.Empty).Equals(LettersOnly().Replace(b, string.Empty), StringComparison.OrdinalIgnoreCase);
    private static bool SameDigits(string a, string b) => DigitsOnly().Replace(a, string.Empty).Equals(DigitsOnly().Replace(b, string.Empty), StringComparison.Ordinal);
    private static string ValidateViewName(string value) => SqlObjectName().IsMatch(value) ? value : throw new InvalidOperationException("MemberDirectory:ViewName contains unsupported characters.");

    [GeneratedRegex("[^\\p{L}]", RegexOptions.CultureInvariant)] private static partial Regex LettersOnly();
    [GeneratedRegex("[^0-9]", RegexOptions.CultureInvariant)] private static partial Regex DigitsOnly();
    [GeneratedRegex("^[A-Za-z0-9_\\[\\]\\.]+$", RegexOptions.CultureInvariant)] private static partial Regex SqlObjectName();
}
