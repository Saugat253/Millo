using Millo.BLL;
using Millo.Filters;
using Millo.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Routing;

namespace Millo.Controllers
{
    public class UserController : ApiController
    {
        private MilloDbContext _dbContext { get; set; }
        public UserController()
        {
            _dbContext = new MilloDbContext();
        }
        
        // GET: api/User
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET: api/User/5
        public string Get(int id)
        {
            return "value";
        }
        [Route("CreateUser")]
        [ValidateModelState]
        // POST: api/User
        public void Post([FromBody]User value)
        {

        }

        // PUT: api/User/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE: api/User/5
        public void Delete(int id)
        {
        }
        [Route("Register")]
        [ValidateModelState]
        public void register(User user)
        {
            PasswordManager passMgr = new PasswordManager();
            passMgr.SecurePassword(user);
            passMgr.MakeJwtTokenKeys(user);
            //var tokenHandler = new JwtSecurityTokenHandler();
            //Claim claim = new Claim("userID",user.UserId);
            //claim
            //ClaimsIdentity claimsIdentity = new System.Security.Claims.ClaimsIdentity();
            //claimsIdentity.AddClaim()
            //tokenHandler.CreateJwtSecurityToken("millo", "", user, "", "", "", user.PublicToken);
            _dbContext.Users.Add(user);
            _dbContext.SaveChangesAsync();
            //var x = GetPrivateAndPublicKey();
        }
        //public Dictionary<string,string> GetPrivateAndPublicKey()
        //{
        //    Dictionary<string, string> keys = new Dictionary<string, string>() ;
        //    Random random = new Random();
        //    string rando= random.Next().ToString();
        //    keys.Add("private", rando);
        //    keys.Add("public", random.NextDouble().ToString());
        //    return keys;

        //}
    }
}
