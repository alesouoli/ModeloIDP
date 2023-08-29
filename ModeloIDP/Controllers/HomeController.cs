using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

using System.Security.Cryptography;
using System.Text;
using System.Configuration;

using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

using System.Net;
using System.Net.Security;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt; /* instalar nuget = identity.model */

namespace ModeloIDP.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var _code = Request.QueryString["code"];

            if (_code != "" && _code != null && _code !="null")
            {
                return Redirect("Home/Callback?code=" + _code);
            }
            else
            {
                return View();
            }
        }

        public ActionResult Redirect()
        {
            string _retorno = String.Empty;
            string _url = ConfigurationManager.AppSettings["IDPAuthority"];
            string _complemento = ConfigurationManager.AppSettings["IDPLoginComplement"];
            string _clientId = ConfigurationManager.AppSettings["IDPClientId"];
            string _redirectURI = Uri.EscapeDataString(ConfigurationManager.AppSettings["IDPRedirectUri"]); /* url encode */

            Random random = new Random(); /* https://christiangiacomi.com/posts/random-hex-strings/ */
            var bytes = new Byte[16];
            random.NextBytes(bytes);

            var hexArray = Array.ConvertAll(bytes, x => x.ToString("X2"));
            var hexStr = String.Concat(hexArray);

            var _state = hexStr.ToLower();

            var rng = RandomNumberGenerator.Create();
            var bytes2 = new byte[32];
            rng.GetBytes(bytes2);

            var _code_verifier = Convert.ToBase64String(bytes2)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            var _codeChallenge = string.Empty;
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(_code_verifier));
                _codeChallenge = Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }

            /* salva na sessao para ser usado depois */

            Session["code_challenge"] = _codeChallenge;
            Session["code_verifer"] = _code_verifier;

            /*
             * URL de exemplo
             * 
             * https://rhsso.idp-hml.sp.gov.br/auth/realms/idpsp/protocol/openid-connect/auth?client_id={client_id}&response_type=code&scope={scope}&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256
             * */
            _retorno = _url + "/" + _complemento + "?client_id=" + _clientId + "&response_type=code&scope=openid+email+phone+profile+govbr_confiabilidades&redirect_uri=" + _redirectURI + "&state=" + _state + "&code_challenge=" + _codeChallenge + "&code_challenge_method=S256";

            return Redirect(_retorno);
        }

        public async Task<ActionResult> Callback()
        {
            string responseString = await this.GetTokenAsync(Request.QueryString["code"]);

            ViewBag.Resposta = responseString;

            JObject jsonObj = JObject.Parse(responseString);

            if (jsonObj.GetValue("id_token") != null)
            {
                var _token = new JwtSecurityTokenHandler().ReadToken((string)jsonObj.GetValue("access_token"));
                var _cpf = ((JwtSecurityToken)_token).Payload["preferred_username"].ToString();
                var _nome = ((JwtSecurityToken)_token).Payload["name"].ToString();
                var _email = ((JwtSecurityToken)_token).Payload["email"].ToString();
                var _telefone = ((JwtSecurityToken)_token).Payload["phone_number"].ToString();

                var _id_token = jsonObj.GetValue("id_token");

                Session["id_token"] = _id_token;
                Session["cpf"] = _cpf;
                Session["nome"] = _nome;
                Session["email"] = _email;
                Session["telefone"] = _telefone;


                return Redirect("Dados");

            }

            return View();
        }


        public async Task<string> GetTokenAsync(String _code)
        {

            var _clientId = ConfigurationManager.AppSettings["IDPClientId"];
            var _clientSecret = ConfigurationManager.AppSettings["IDPClientSecret"];
            var _redirectUri = ConfigurationManager.AppSettings["IDPRedirectUri"];
            var _urlToken = ConfigurationManager.AppSettings["IDPAuthority"] + "/" + ConfigurationManager.AppSettings["IDPTokenComplement"];

            var _codeVerifier = Session["code_verifer"].ToString();

            var _values = new Dictionary<string, string>
            {
                {"client_id", _clientId},
                {"redirect_uri", _redirectUri},
                {"grant_type", "authorization_code"},
                {"code", _code},
                {"code_verifier", _codeVerifier}
            };


            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

            /*
            var _ipProxy = ConfigurationManager.AppSettings["IPProxy"];

            var proxy = new WebProxy
            {
                Address = new Uri(_ipProxy),
                BypassProxyOnLocal = false,
                UseDefaultCredentials = true,
                // Credentials = new NetworkCredential(userName: proxy_user, password: proxy_pass)
            };

            var handler = new HttpClientHandler { Proxy = proxy }; */

            HttpClient _httpClient = null;

            try
            {
                _httpClient = new HttpClient { Timeout = TimeSpan.FromMilliseconds(60000) };
                //_httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(60000) };

                _httpClient.DefaultRequestHeaders.Add("authorization", $"Basic {Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_clientId}:{_clientSecret}"))}");


                var content = new FormUrlEncodedContent(_values);


                /* https://pt.stackoverflow.com/questions/83226/net-c-iis-a-solicitação-foi-anulada-não-foi-possível-criar-um-canal-seguro-pa *
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Ssl3;
                ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true; */


                var response = await _httpClient.PostAsync(_urlToken, content);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    return responseContent;
                }


                throw new Exception("A solicitação de token falhou com o código de status: " + response.StatusCode);
            }
            finally
            {
                if (_httpClient != null)
                {
                    _httpClient.Dispose();
                }
            }

        }

        public ActionResult Dados()
        {
            ViewBag.CPF = (string)Session["cpf"];
            ViewBag.Nome = (string)Session["nome"];
            ViewBag.Email = (string)Session["email"];
            ViewBag.Telefone = (string)Session["telefone"];

            return View();
        }

        public ActionResult Logout()
        {
            string _retorno = String.Empty;
            string _id_token = Session["id_token"].ToString();
            string _url =  ConfigurationManager.AppSettings["IDPAuthority"];
            string _complementoLogout = ConfigurationManager.AppSettings["IDPLogoutComplement"];
            string _redirectURI = Uri.EscapeDataString(ConfigurationManager.AppSettings["IDPRedirectUri"]);

            _retorno = _url + "/" + _complementoLogout + "?id_token_hint=" + _id_token + "&post_logout_redirect_uri=" + _redirectURI;

            ViewBag.Retorno = _retorno;

 

            return Redirect(_retorno);
        }
    }
}