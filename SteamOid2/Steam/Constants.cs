using SteamOid2.XRI;

namespace SteamOid2.Steam;

/// <summary>
/// Defines constants related to Steam's OpenID authentication.
/// </summary>
public static class Constants
{
    /// <summary>
    /// URL to the XRI provider which provides resource for OpenID authentication.
    /// </summary>
    public const string SteamXRIProvider = "https://steamcommunity.com/openid";

    /// <summary>
    /// Prefix of the URL returned from Steam's OpenID authentication used to retreive the Steam64 ID.
    /// </summary>
    public const string SteamClaimedIdPrefix = "https://steamcommunity.com/openid/id/";
    internal static readonly SteamOid2Resource BackupSteamOid2Resource = new("http://specs.openid.net/auth/2.0/server", "https://steamcommunity.com/openid/login");
}