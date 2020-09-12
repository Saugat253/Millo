using Millo.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Millo.BLL
{
    public class PasswordManager
    {
        MilloDbContext milloDb = new MilloDbContext();
        private string _passwordHash { get; set; }
        public string _password { get; set; }
        public int _salt { get; set; }
        public PasswordManager(string strPassword, int nSalt)
        {
            _password = strPassword;
            _salt = nSalt;
        }
        public PasswordManager()
        {

        }

        public async Task<User> SecurePassword(User user)
        {
            string pass = user.Password;
            if (user.Password != null)
            {
                pass = user.Password;
            }
            try
            {
                int salt = await CreateRandomSalt();
                _password = pass;
                _salt = salt;

                user.PasswordHash = await ComputeSaltedHash();
                user.PasswordSalt = _salt.ToString();
                user.Password = "";


                return user;
            }
            catch (Exception)
            {

                throw;
            }
        }
        public User GetUserByUserName(string userName)
        {
            User user;
            user = milloDb.Users.Where(x => x.UserName == userName || x.Email == userName).FirstOrDefault();
            return user;
        }
        public async Task<string> CreateRandomPassword(int PasswordLength)
        {
            String _allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789";
            Byte[] randomBytes = new Byte[PasswordLength];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            char[] chars = null;
            await Task.Run(() =>
            {
                rng.GetBytes(randomBytes);
                chars = new char[PasswordLength];
                int allowedCharCount = _allowedChars.Length;

                for (int i = 0; i < PasswordLength; i++)
                {
                    chars[i] = _allowedChars[(int)randomBytes[i] % allowedCharCount];
                }
            });
            return new string(chars);
        }
        public async Task<int> CreateRandomSalt()
        {
            Byte[] _saltBytes = new Byte[4];
            await Task.Run(() =>
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(_saltBytes);
            });
            return ((((int)_saltBytes[0]) << 24) + (((int)_saltBytes[1]) << 16) +
              (((int)_saltBytes[2]) << 8) + ((int)_saltBytes[3]));
        }

        public async Task<string> ComputeSaltedHash()
        {
            // Create Byte array of password string
            ASCIIEncoding encoder = new ASCIIEncoding();
            Byte[] _secretBytes = encoder.GetBytes(_password);

            // Create a new salt
            Byte[] _saltBytes = new Byte[4];
            await Task.Run(() =>
            {
                _saltBytes[0] = (byte)(_salt >> 24);
                _saltBytes[1] = (byte)(_salt >> 16);
                _saltBytes[2] = (byte)(_salt >> 8);
                _saltBytes[3] = (byte)(_salt);
            });
            // append the two arrays
            Byte[] toHash = new Byte[_secretBytes.Length + _saltBytes.Length];
            string plaintext = string.Empty;
            await Task.Run(() =>
            {
                Array.Copy(_secretBytes, 0, toHash, 0, _secretBytes.Length);
                Array.Copy(_saltBytes, 0, toHash, _secretBytes.Length, _saltBytes.Length);

                SHA1 sha1 = SHA1.Create();
                Byte[] computedHash = sha1.ComputeHash(toHash);
                plaintext = Convert.ToBase64String(computedHash);
                //return encoder.GetString(plaintext);
                _passwordHash = plaintext;
            });
            return plaintext;
        }
        public async Task<User> CheckPassword(string username, string password)
        {
            bool isCorrect = false;
            User user = null;
            await Task.Run(() => user = GetUserByUserName(username));
            user.Password = password;
            bool hash = await CheckUserHash(user);
            if (hash)
            {
                return user;
            }
            else
            {
                user = null;
            }
            return user;
        }

        private async Task<bool> CheckUserHash(User user)
        {
            string finalHash = string.Empty;
            bool CorrectUser = false;
            _password = user.Password;
            _salt = Convert.ToInt32(user.PasswordSalt);
            await Task.Run(async () =>
            {
                finalHash = await ComputeSaltedHash();
                user.Password = "";
            });
            if (finalHash == user.PasswordHash)
            {
                return true;
            }
            else
                return false;
        }

        public async Task<User> MakeJwtTokenKeys(User user)
        {
            if (_passwordHash == null)
            {
                _passwordHash = user.PasswordHash;
            }
            _password = _passwordHash;
            await CreateRandomSalt();
            user.PrivateToken = await ComputeSaltedHash();
            await CreateRandomSalt();
            _password = _passwordHash;
            user.PublicToken = await ComputeSaltedHash();
            user.Password = "";
            return user;

        }
    }
}