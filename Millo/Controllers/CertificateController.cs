
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web.Http;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Millo.Controllers
{
    [RoutePrefix("Certificate")]
    public class CertificateController : ApiController
    {
        private static RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        // GET: api/Certificate
        public IEnumerable<string> Get()
        {

            return new string[] { "value1", "value2" };
        }
        [HttpGet, Route("CreateCertificate")]
        public IEnumerable<string> CreateCertificate()
        {

            // service url to call
            string _url = "http://localhost:1254/values";

            // the token issuer urn, and the audience urn I intend this token for
            string _issuer = "http://my.tokenissuer.com";
            string _audience = "https://my.company.com";

            // load in the private key certificate from the local file or database
            string path = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
            var directory = System.IO.Path.GetDirectoryName(path);
            var certFile = (directory + "\\Certificate\\CourseCert.pfx").ToString();
            certFile = (directory + "\\Certificate\\CourseCert.pfx").Substring(6);
            //var cert = CertificateHelper.FindByThumbprint(""Ž"Ž"Ž"Žb29fde59011709518392183bc643431262a9dd5e", StoreName.My, StoreLocation.LocalMachine);
            var certificate = new X509Certificate2();
            certificate.Import(certFile, "abc12345", X509KeyStorageFlags.PersistKeySet);

            // Create a digital signing key from the secret key in the certificate
            var signingCredentials = new X509SecurityKey(certificate);

            // create some claims to put into the token
            var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, "TestUserName"),
                    new Claim(ClaimTypes.Email, "testuser@mycompany.com"),
                    new Claim("MyCustomClaim", "My special value"),
                };

            // define the token elements -- claims, signing key, lifetime, issuer, etc.
            var securityTokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor()
            {
                Audience = _audience,
                Issuer = _issuer,
                Subject = new ClaimsIdentity(claims, "Bearer"),
                SigningCredentials = new SigningCredentials(signingCredentials,
                                        SecurityAlgorithms.RsaSha256Signature),
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                Expires = DateTime.UtcNow.AddHours(12)
            };

            // create the token, digitally sign it, and write it out to a string
            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(securityTokenDescriptor);
            var tokenString = handler.WriteToken(token);

            Console.WriteLine(tokenString);

            // now we have a JWT string, let's make our REST call
            var task = Task.Run(async () => await GetValuesAsync(_url, tokenString));
            var values = task.Result;

            foreach (var s in values)
                Console.WriteLine(s);
            Console.ReadKey();



            /// <summary>
            /// internal async method to call the rest service URL with the token attached
            /// with "Bearer" token scheme.
            /// </summary>


            return new string[] { "value1", "value2" };
        }
        static async Task<List<string>> GetValuesAsync(string path, string token)
        {
            List<string> values = new List<string>();
            var client = new HttpClient();

            client.BaseAddress = new Uri(path);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                "Bearer", token);

            HttpResponseMessage response = await client.GetAsync(path);
            if (response.IsSuccessStatusCode)
                values = await response.Content.ReadAsAsync<List<string>>();
            else
                values.Add(response.ToString());
            return values;
        }
        // GET: api/Certificate/5
        public string Get(int id)
        {
            return "value";
        }

        // POST: api/Certificate
        public void Post([FromBody] string value)
        {
        }

        // PUT: api/Certificate/5
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE: api/Certificate/5
        public void Delete(int id)
        {
        }
    }
}
