using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Millo.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml.Serialization;

namespace Millo.BLL
{
    public class JwtRsaTokenManager
    {
        public User _user { get; set; }
        public JwtRsaTokenManager(User user)
        {
            _user = user;
        }
        public JwtRsaTokenManager()
        {

        }
        public User InsertRsaKeys()
        {
            RsaPrivateAndPublicKeyGenerator rsaPrivateAndPublicKeyGenerator = new RsaPrivateAndPublicKeyGenerator();
            _user.Password = "";
            _user.PrivateToken = rsaPrivateAndPublicKeyGenerator.PrivateKeyString();
            _user.PublicToken = rsaPrivateAndPublicKeyGenerator.PublicKeyString();
            return _user;
        }

        public string CreateToken(User user)
        {
            string token = string.Empty;
            JwtTokenCreator jwtTokenCreator = new JwtTokenCreator();
            string PrivateKey = user.PrivateToken;

            var claims = new Claim[]
           {
               new Claim("Id",user.UserId.ToString()),
                new Claim("UserName",user.UserName),
                new Claim("Role",user.Role),
                new Claim("FullName",user.FirstName + " "+user.LastName),
                
           };
            jwtTokenCreator.writeToken(PrivateKey, claims,user.UserName);
            return token;
        }
    }




    class CreateSecureToken
    {
        string sec = "bhgjhghjkhgkhgjghkhgjkhkjhgjghkjghkjhkjgytr6u4435234534535yretrttyutytrytetuytuiytyuit76434yyrureytrtyerytreureu1234567890hjhjgfdsaProEMLh5e_qnzdNUrqdHP";
        string sec1 = "ProEMLh5e_qnzdNU";
        string privateKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgAgACAAPABQAD4AKwBxAEUAaABPAEQAeABmAEsAegBMAEgAZwBVADkASQBoAEgAZwA2AFkAagBCAGMAdgBwAFcASwBGAG4AbABnAGEANQBZADEAagBLAEEAMAArADgAUQBWADgAWgByADcAWgBlAHYAaABMAEIAdAAzAHQASgBLAGUAZwArAGcATgB4AGIAUwBCAHEAQQB5AHIAKwA5ADUAdwB3AE0AcQBNAGoAdQBvAHgANgBSAGkAVgBGAFMANABmAEwANwAzAGgALwBHAEoAcQB6AFgASABpAFkAcgBQAEQAOQBkAHUANwBPADAASQBWAFUAcABCAEIASgBrAC8ASgAvAGEAYwAwADYAeQBlAGQAMQA2AEQAWgBSAE4AdABFAGgATwBJAFYAVAAzAFQAZgAzAGQATwBSAEwAOABDAGYAVQB3AE8ANQBlAHQAQgB3AFAANgBQAHkAagA2ADgAPQA8AC8AUAA+AA0ACgAgACAAPABRAD4AOABhAHgAegAyAEkAYQBzAGgAZQBTAFEAQQBwADYAOABPAFUASwAxAHMAOQB0AGYAaAAvAHoAdwBWAFEATwBwAEEAMgBWAFEAawBFAGkAWQA0AE4AdwBnADkAOQAvAFUAVAA1AFgARwB1ADMATQB1AEUATgBlAFIAVgBLAE4AUgBDAFYAZQBVAE0AegBPAEcAMwBlAFIANwBMAHkANQBBAFEATABxAEkAbAAzADEAcQBGAEYAbAB6AGoANABsADQARQB1AEsASAB0AGQAbwBXADMAdgA3AFUAUgBHAHMAbwBkADQATQA2AGwAeQArAC8AWABzAHgAaQBjADAAdAAxAFUAOQBnADcAawBjAHQAcAB2AHIAeQArAHIARABuAEQARgBHADEALwBnADcAYgBqAFYAagBMAEoAbgBjADgATgB6AE0AMgAzAHIASgBZADEAWABYAHMAPQA8AC8AUQA+AA0ACgAgACAAPABEAFAAPgBEAGYAaABQAFIAcgBnAHUAdwBkAFMAcAB4AEMANQBzAEoAMQA0AGcATwB2AHIAaABJAEkAcAByAFUAUQBkAGcAOQBYADUAQQA2ADkANgArAE4AVQA1AGYAdgBzAEQAWgB4AEgAdQBhAGEASAAvADcAYwB5AGcAOQBCADcATQAyAG0AVQArAFAAYgBwAE8ATwBQAHAATABPAGoAQwBCACsASgB6AFUAcwBwAFEAYQBHAHcATgBCADYAVQBvAG4AdAAvADgAaABvAGwAWgAwAEUAZABtAFgANAB4AFUAcQBEAEwARABGAHAAeQBOAGwAYgBtAEUAdwBZAFEAVABoAEIAdgBkADMATwBjAFkAZAA0AHQATgByAFgALwBlAFEAdwBOAGUAYQBZADEAOQArAEUARgB6AHAAUQBaAHkAcwBzACsAbwBpAEYAeQBUAFoAVgBQAGUAYwA9ADwALwBEAFAAPgANAAoAIAAgADwARABRAD4ASwA0AEMAawBkAGMAUwBBAFIANwBYAEYANgBvAEwAUwBWAE8AaABhAE4AdAA3ADEAUwBsAEIAUQBuAHEAMABDAC8AbgBaADkAVQB3AHUATwBZAFcATwBlAGwANQAvADEANABzAEcATwBQAFcAMwBWAFMALwBqAFIAMAAwADkAMgBwAGQAegBhADgANABDAEIAOQBXADEATQBjADAAaQA3AEQAaQB2AEYAcgBLAGQASgBzAGgASQBNAEMARABsAHgAbwBNAHkAZwBLAHkANwB2ADAAUQBKAEUAQwBYAEQAVQBuAHYAYgBEAFYARABXAG4ARwBCAFIAbwBZAEcASwBqADQAdwB6AFkAWgBEADAAZQBjAHQAUQBjADYAbgBtAFgAVQBSAFUASQAwAEIAZgBhAHcAawBoAHcASABIAFUASwBBAGUAVABCAC8ARgBJAHAAbAB3AE0APQA8AC8ARABRAD4ADQAKACAAIAA8AEkAbgB2AGUAcgBzAGUAUQA+AGIAMgBoAEcAZQBtAEgAMABoADUAVABoAHkAbABhAFMAeQB4AHMARQAxAFoAdQBtAFQAawB0ADQASAA2ADMAUwBXAFAAVQBRAEYAeQB6AFIANwB6AGMAOABlAHkAdABiAEQAUQB4AGEAOQA5AFMAVABsAGYAWgBSAFcAYwB2AGEAZwAvADUANwBrAEwAYgBGAG8AaABhADEAZwBLAFMATQBlAG8AMAB0AGIAdQBYAEsAYwA3ACsAZQAvADUAYwBiAG0AUAA3AFMAVgBnAC8AUgBnADgAZAA2AGkAdgBZACsAKwBCADgAcgBGAEgAcwBtAEQAcwBIAHAAVgBHAEgAMABhADUARABEAGoAbQBjAEoASgBnAFQARwAzADUAcgA0AHIAZAAxAEsAMgAwAGYAcQBGADYAOAAvAHcAZAAwAHcARgBpAEoAOQBIAHUAcQArAEwANQBrAD0APAAvAEkAbgB2AGUAcgBzAGUAUQA+AA0ACgAgACAAPABEAD4AYQBGAHEASwA0ADQAVQBXAHkAQgA4AFEARAB6AE0ATgBZAFAAZwBpAE0AZwAzAGQAUgBLAHcAUgBCADEAeQBPAEkAZQB2AFoAagBDAGwAUwBhAEUAWQAwADMAWQBTAEcAWQAxAGIAaQBMADcAcQB1AHQAWABaAG0AZwBLAGUATwBWAFUAdgBVAHMAYwBpADAATAB2ADAAeAA2AE4AWABZAHQAOQB1AHYAbgB6AGwAYQBzAFcAaQB5ADkAegBLAGoAZwBvAGEAaQB3AEMANABDAEkAWgAxAFgARwBPAHgANwA4AHUAYwBEAG8AbwA0AEkAOABTAEEAQwAvAFAANwBVAGQAWQBaADkAMQBLAHEAeQBZAEkAYwBEAHYARQAzADMANQA5AGkAVQB2AFMAYQBWAE4AWgBHAEkAVQBCAGcAUAByAGoAVgBrAHcAOABrAEgAZgBlAGUARgB3AEQAcwBWADcAYwBWAEUAcABSAEgAcAAxADQAOABCADUAaABZAEgAawBOAEMAMQBVACsANAB6AG8ASABwADcAaABZACsANQBkAE8AMQBqAEMASABEADEAdwBhAG4AKwBOAHkARQBMAGcATQB4AG0AbwBiAGEASgBOAFIAOQBXAGcATABwAFoAcgB2AFQASABPADQASABLAGYASQB4AEEAdwBGAE8ARwBBADgAbwBrAEUAaABpAHIAWQBoAHkAQwAwADQAbwA1AFQAQQArAHIAKwBkAG8AMABEAEIAVAB2AHYAWABTAHEAbQBtAGgANABvADUAeABGAGYARgBRADMAeQBxAHAARwBtAE8ANgBmAEcAbgBPADgATQBFAGMAUgB2AGUAQwBsAFUAcQBmAHEAdQBtAFQAWABvAEYAaQBYAFIAZQBIAHcAMQA2AGwAMAB6AFEAPQA9ADwALwBEAD4ADQAKADwALwBSAFMAQQBQAGEAcgBhAG0AZQB0AGUAcgBzAD4A";
        string publicKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgA8AC8AUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwA+AA==";
        public CreateSecureToken(string PrivateKey, string PublicKey)
        {
            privateKey = PrivateKey;
            publicKey = PublicKey;
        }
        public CreateSecureToken()
        {

        }
        public JwtSecurityToken encryptToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sec1));

            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512);

            List<Claim> claims = new List<Claim>()
                {
                    new Claim("sub", "test"),
                };

            var ep = new EncryptingCredentials(
                securityKey1,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JwtSecurityTokenHandler();

            var jwtSecurityToken = handler.CreateJwtSecurityToken(
                "issuer",
                "Audience",
                new ClaimsIdentity(claims),
                DateTime.Now,
                DateTime.Now.AddDays(2000),
                DateTime.Now,
                signingCredentials,
                ep);
            string tokenString = handler.WriteToken(jwtSecurityToken);
            // Id someone tries to view the JWT without validating/decrypting the token,
            // then no claims are retrieved and the token is safe guarded.
            //Console.Writeline("Id someone tries to view the JWT without validating/decrypting the token");
            var jwt = new JwtSecurityToken(tokenString);
            Console.ReadLine();
            return jwt;
        }
        public SecurityToken decryptToken(string token)
        {

            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec1));

            // This is the input JWT which we want to validate.
            string tokenString = string.Empty;
            tokenString = token;
            // If we retrieve the token without decrypting the claims, we won't get any claims
            // DO not use this jwt variable
            var jwt = new JwtSecurityToken(tokenString);

            // Verification
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                {
                    "Audience"
                },
                ValidIssuers = new string[]
                {
                    "issuer"
                },
                IssuerSigningKey = securityKey,
                // This is the decryption key
                TokenDecryptionKey = securityKey1
            };

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            var isCorrect = handler.CanValidateToken;
            var x = handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);
            return validatedToken;
        }
        public string createUncrackableToken()
        {
            List<Claim> claims = new List<Claim>()
                {
                    new Claim("sub", "test"),
                };
            var scKey = Encoding.UTF8.GetBytes(privateKey);
            var ecKeyTemp = Encoding.UTF8.GetBytes(publicKey);

            // Note that the ecKey should have 256 / 8 length:
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(ecKeyTemp, ecKey, 256 / 8);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(
                        scKey),
                        SecurityAlgorithms.HmacSha512),
                EncryptingCredentials = new EncryptingCredentials(
                    new SymmetricSecurityKey(
                        ecKey),
                        SecurityAlgorithms.Aes256KW,
                        SecurityAlgorithms.Aes256CbcHmacSha512),
                Issuer = "My Jwt Issuer",
                Audience = "My Jwt Audience",
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.Now.AddDays(7),
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);
            return jwt;

        }
        public SecurityToken DecryptUncrackableToken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(privateKey));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(publicKey));

            // This is the input JWT which we want to validate.
            string tokenString = string.Empty;
            tokenString = token;
            // If we retrieve the token without decrypting the claims, we won't get any claims
            // DO not use this jwt variable
            var jwt = new JwtSecurityToken(tokenString);
            var ecKeyTemp = Encoding.UTF8.GetBytes(publicKey);

            // Note that the ecKey should have 256 / 8 length:
            byte[] ecKey = new byte[256 / 8];
            Array.Copy(ecKeyTemp, ecKey, 256 / 8);
            securityKey1 = new SymmetricSecurityKey(ecKey);
            // Verification
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[]
                   {
                    "My Jwt Audience"
                   },
                ValidIssuers = new string[]
                   {
                    "My Jwt Issuer"
                   },
                IssuerSigningKey = securityKey,
                // This is the decryption key
                TokenDecryptionKey = securityKey1
            };

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            var isCorrect = handler.CanValidateToken;
            var x = handler.ValidateToken(tokenString, tokenValidationParameters, out validatedToken);

            return validatedToken;
        }

    }
    class JwtTokenCreator
    {
        string publicKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgA8AC8AUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwA+AA==";
        string payload = "user= ashish, password=ashish123";
        string privateKey = @"PAA/AHgAbQBsACAAdgBlAHIAcwBpAG8AbgA9ACIAMQAuADAAIgAgAGUAbgBjAG8AZABpAG4AZwA9ACIAdQB0AGYALQAxADYAIgA/AD4ADQAKADwAUgBTAEEAUABhAHIAYQBtAGUAdABlAHIAcwAgAHgAbQBsAG4AcwA6AHgAcwBpAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEALQBpAG4AcwB0AGEAbgBjAGUAIgAgAHgAbQBsAG4AcwA6AHgAcwBkAD0AIgBoAHQAdABwADoALwAvAHcAdwB3AC4AdwAzAC4AbwByAGcALwAyADAAMAAxAC8AWABNAEwAUwBjAGgAZQBtAGEAIgA+AA0ACgAgACAAPABFAHgAcABvAG4AZQBuAHQAPgBBAFEAQQBCADwALwBFAHgAcABvAG4AZQBuAHQAPgANAAoAIAAgADwATQBvAGQAdQBsAHUAcwA+ADcASgBxAEYAOABxAEIAWABzAE8AagBBAHgAbQBwAFcAWQB6AEMASgBIAHAAbQBlADMAWgBZAFMAaQBtAGgAQgBZAGoAWAB1AGwAbwBqAFMAWQBFAGIAVAAxAEcAYwBFADUAWQBEAGkAeQBaAG8AQwA0ADMAYwBLAGoAcgB2AEUAeABrAHoANwBRAGkAQgA4AFcAQQB2ADcAYQBaAHoAZgBmAEIAeAB4AFcAdABWAEUASQAvAHoAaQB3ADMARwBsAE0AZAByAG0AOAA2AC8AcgAzADkAMABUAGIATQBPAGgAMwBkAHUARAAvAEcALwBOAEgAcwBqACsASAAxAG4ASwB6ADMAYwBrAFkAbQBJAC8ASgBBAE8AdgB5AGUASQB3AHgAOAA4AG0AOQBUAEsAaQA2AE4AMQBCAEoANQBuAG0ATABUAEkAbABWAFEAZgBIAFQAdgBBAEoAMwBUAHcAaABBAE8AMgB3AGQATgAwAFcALwBTAGwAMgA4AHYAawBRAFMAYQBVAC8AOABiAG8ATQA5AFkAZwBuAFgAQQAzAGIAcwBmAFoAegBoAGUAYgBIAGYAbAA2AFgAYQBhADcAeABOACsAZQA0AG8ASABxADEAdwB2AE4ASgBUAGUAWABBAFIASABaADIAcgBTAEoAMQBaAEEAUQBHAG0AcABLAEwAVwBYAGEAWABuAEUAQgBIAFgAZwBZAFUAcwBLAFQAZABtAGUAYwBRAHgAUQBKAFUATABSAGMATQBIAEYAbAA4ADAAcwBkAFgAbQBNAEkAeQB3AHgANwBEAHUAMwBOAEoANQAzAE0AOQBFAEoANwBGAHgARgBPAGUALwBpAFEAMgBQAEIAZwBYAEgAMABGAFIAQgBEAHgAUQArADgARQBmAEwAUABpAGMARgBRAD0APQA8AC8ATQBvAGQAdQBsAHUAcwA+AA0ACgAgACAAPABQAD4AKwBxAEUAaABPAEQAeABmAEsAegBMAEgAZwBVADkASQBoAEgAZwA2AFkAagBCAGMAdgBwAFcASwBGAG4AbABnAGEANQBZADEAagBLAEEAMAArADgAUQBWADgAWgByADcAWgBlAHYAaABMAEIAdAAzAHQASgBLAGUAZwArAGcATgB4AGIAUwBCAHEAQQB5AHIAKwA5ADUAdwB3AE0AcQBNAGoAdQBvAHgANgBSAGkAVgBGAFMANABmAEwANwAzAGgALwBHAEoAcQB6AFgASABpAFkAcgBQAEQAOQBkAHUANwBPADAASQBWAFUAcABCAEIASgBrAC8ASgAvAGEAYwAwADYAeQBlAGQAMQA2AEQAWgBSAE4AdABFAGgATwBJAFYAVAAzAFQAZgAzAGQATwBSAEwAOABDAGYAVQB3AE8ANQBlAHQAQgB3AFAANgBQAHkAagA2ADgAPQA8AC8AUAA+AA0ACgAgACAAPABRAD4AOABhAHgAegAyAEkAYQBzAGgAZQBTAFEAQQBwADYAOABPAFUASwAxAHMAOQB0AGYAaAAvAHoAdwBWAFEATwBwAEEAMgBWAFEAawBFAGkAWQA0AE4AdwBnADkAOQAvAFUAVAA1AFgARwB1ADMATQB1AEUATgBlAFIAVgBLAE4AUgBDAFYAZQBVAE0AegBPAEcAMwBlAFIANwBMAHkANQBBAFEATABxAEkAbAAzADEAcQBGAEYAbAB6AGoANABsADQARQB1AEsASAB0AGQAbwBXADMAdgA3AFUAUgBHAHMAbwBkADQATQA2AGwAeQArAC8AWABzAHgAaQBjADAAdAAxAFUAOQBnADcAawBjAHQAcAB2AHIAeQArAHIARABuAEQARgBHADEALwBnADcAYgBqAFYAagBMAEoAbgBjADgATgB6AE0AMgAzAHIASgBZADEAWABYAHMAPQA8AC8AUQA+AA0ACgAgACAAPABEAFAAPgBEAGYAaABQAFIAcgBnAHUAdwBkAFMAcAB4AEMANQBzAEoAMQA0AGcATwB2AHIAaABJAEkAcAByAFUAUQBkAGcAOQBYADUAQQA2ADkANgArAE4AVQA1AGYAdgBzAEQAWgB4AEgAdQBhAGEASAAvADcAYwB5AGcAOQBCADcATQAyAG0AVQArAFAAYgBwAE8ATwBQAHAATABPAGoAQwBCACsASgB6AFUAcwBwAFEAYQBHAHcATgBCADYAVQBvAG4AdAAvADgAaABvAGwAWgAwAEUAZABtAFgANAB4AFUAcQBEAEwARABGAHAAeQBOAGwAYgBtAEUAdwBZAFEAVABoAEIAdgBkADMATwBjAFkAZAA0AHQATgByAFgALwBlAFEAdwBOAGUAYQBZADEAOQArAEUARgB6AHAAUQBaAHkAcwBzACsAbwBpAEYAeQBUAFoAVgBQAGUAYwA9ADwALwBEAFAAPgANAAoAIAAgADwARABRAD4ASwA0AEMAawBkAGMAUwBBAFIANwBYAEYANgBvAEwAUwBWAE8AaABhAE4AdAA3ADEAUwBsAEIAUQBuAHEAMABDAC8AbgBaADkAVQB3AHUATwBZAFcATwBlAGwANQAvADEANABzAEcATwBQAFcAMwBWAFMALwBqAFIAMAAwADkAMgBwAGQAegBhADgANABDAEIAOQBXADEATQBjADAAaQA3AEQAaQB2AEYAcgBLAGQASgBzAGgASQBNAEMARABsAHgAbwBNAHkAZwBLAHkANwB2ADAAUQBKAEUAQwBYAEQAVQBuAHYAYgBEAFYARABXAG4ARwBCAFIAbwBZAEcASwBqADQAdwB6AFkAWgBEADAAZQBjAHQAUQBjADYAbgBtAFgAVQBSAFUASQAwAEIAZgBhAHcAawBoAHcASABIAFUASwBBAGUAVABCAC8ARgBJAHAAbAB3AE0APQA8AC8ARABRAD4ADQAKACAAIAA8AEkAbgB2AGUAcgBzAGUAUQA+AGIAMgBoAEcAZQBtAEgAMABoADUAVABoAHkAbABhAFMAeQB4AHMARQAxAFoAdQBtAFQAawB0ADQASAA2ADMAUwBXAFAAVQBRAEYAeQB6AFIANwB6AGMAOABlAHkAdABiAEQAUQB4AGEAOQA5AFMAVABsAGYAWgBSAFcAYwB2AGEAZwAvADUANwBrAEwAYgBGAG8AaABhADEAZwBLAFMATQBlAG8AMAB0AGIAdQBYAEsAYwA3ACsAZQAvADUAYwBiAG0AUAA3AFMAVgBnAC8AUgBnADgAZAA2AGkAdgBZACsAKwBCADgAcgBGAEgAcwBtAEQAcwBIAHAAVgBHAEgAMABhADUARABEAGoAbQBjAEoASgBnAFQARwAzADUAcgA0AHIAZAAxAEsAMgAwAGYAcQBGADYAOAAvAHcAZAAwAHcARgBpAEoAOQBIAHUAcQArAEwANQBrAD0APAAvAEkAbgB2AGUAcgBzAGUAUQA+AA0ACgAgACAAPABEAD4AYQBGAHEASwA0ADQAVQBXAHkAQgA4AFEARAB6AE0ATgBZAFAAZwBpAE0AZwAzAGQAUgBLAHcAUgBCADEAeQBPAEkAZQB2AFoAagBDAGwAUwBhAEUAWQAwADMAWQBTAEcAWQAxAGIAaQBMADcAcQB1AHQAWABaAG0AZwBLAGUATwBWAFUAdgBVAHMAYwBpADAATAB2ADAAeAA2AE4AWABZAHQAOQB1AHYAbgB6AGwAYQBzAFcAaQB5ADkAegBLAGoAZwBvAGEAaQB3AEMANABDAEkAWgAxAFgARwBPAHgANwA4AHUAYwBEAG8AbwA0AEkAOABTAEEAQwAvAFAANwBVAGQAWQBaADkAMQBLAHEAeQBZAEkAYwBEAHYARQAzADMANQA5AGkAVQB2AFMAYQBWAE4AWgBHAEkAVQBCAGcAUAByAGoAVgBrAHcAOABrAEgAZgBlAGUARgB3AEQAcwBWADcAYwBWAEUAcABSAEgAcAAxADQAOABCADUAaABZAEgAawBOAEMAMQBVACsANAB6AG8ASABwADcAaABZACsANQBkAE8AMQBqAEMASABEADEAdwBhAG4AKwBOAHkARQBMAGcATQB4AG0AbwBiAGEASgBOAFIAOQBXAGcATABwAFoAcgB2AFQASABPADQASABLAGYASQB4AEEAdwBGAE8ARwBBADgAbwBrAEUAaABpAHIAWQBoAHkAQwAwADQAbwA1AFQAQQArAHIAKwBkAG8AMABEAEIAVAB2AHYAWABTAHEAbQBtAGgANABvADUAeABGAGYARgBRADMAeQBxAHAARwBtAE8ANgBmAEcAbgBPADgATQBFAGMAUgB2AGUAQwBsAFUAcQBmAHEAdQBtAFQAWABvAEYAaQBYAFIAZQBIAHcAMQA2AGwAMAB6AFEAPQA9ADwALwBEAD4ADQAKADwALwBSAFMAQQBQAGEAcgBhAG0AZQB0AGUAcgBzAD4A";


        public JwtTokenCreator()
        {

        }
        public JwtTokenCreator(string PrivateKey, string PublicKey, Claim[] claims)
        {
            publicKey = PublicKey;
            privateKey = PrivateKey;

        }
        public string writeToken(string pvtkey, Claim[] claims,string username)
        {
            JwtTokenCreator jwtTokenCreator = new JwtTokenCreator();
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            privateKey = pvtkey;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(privateKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jwtToken = new JwtSecurityToken("Millo",username, claims, DateTime.Now, DateTime.Now.AddDays(2000), credentials);
            //Console.Writeline(new JwtSecurityTokenHandler().WriteToken(jwtToken));
            var jwt = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            return jwt;
        }
    }
    class RsaPrivateAndPublicKeyGenerator
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        public RsaPrivateAndPublicKeyGenerator()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);

        }
        public string PublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            var x = Encoding.Unicode.GetBytes(sw.ToString());
            var publicKey = Convert.ToBase64String(x);
            return publicKey.ToString();
        }
        public string PrivateKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);
            var x = Encoding.Unicode.GetBytes(sw.ToString());
            var privateKey = Convert.ToBase64String(x);
            return privateKey.ToString();
        }
        public string Encrypt(string plainText)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);
            return Convert.ToBase64String(cypher);
        }
        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);
            var plain = csp.Decrypt(dataBytes, false);
            return Encoding.Unicode.GetString(plain);
        }


    }

}