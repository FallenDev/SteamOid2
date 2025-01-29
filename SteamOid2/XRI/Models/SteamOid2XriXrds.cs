using System.Xml.Serialization;

namespace SteamOid2.XRI.Models;

internal class SteamOid2Xri
{
    public SteamOid2XriXrds? XRDS { get; set; }
}
internal abstract class SteamOid2XriXrds
{
    [XmlArray("Service")]
    public SteamOid2XriService[]? XRD { get; set; }
}
internal class SteamOid2XriService
{
    [XmlAttribute("priority")]
    public int Priority { get; set; }

    public string? Type { get; set; }
    public string? URI { get; set; }
}
