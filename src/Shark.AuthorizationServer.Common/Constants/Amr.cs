namespace Shark.AuthorizationServer.Common.Constants;

public static class Amr
{
    public const string Face = "face";

    public const string Fpt = "fpt";

    public const string Geo = "geo";

    public const string Hwk = "hwk";

    public const string Iris = "iris";

    public const string Kba = "kba";

    public const string Mca = "mca";

    public const string Mfa = "mfa";

    public const string Otp = "otp";

    public const string Pin = "pin";

    public const string Pwd = "pwd";

    public const string Rba = "rba";

    public const string Retina = "retina";

    public const string Sc = "sc";

    public const string Sms = "sms";

    public const string Swk = "swk";

    public const string Tel = "tel";

    public const string User = "user";

    public const string Vbm = "vbm";

    public const string Wia = "wia";

    public const string Custom = "custom";

    public readonly static HashSet<string> Supported = new HashSet<string>
    {
        Face, Fpt, Geo, Hwk, Iris, Kba, Mca, Mfa, Otp, Pin, Pwd, Rba, Retina, Sc, Sms, Swk, Tel, User, Vbm, Wia,
    };
}