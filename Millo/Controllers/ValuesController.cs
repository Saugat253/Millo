using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Routing;
using Millo.Filters.AuthenticationFilter;
using Millo.Handlers;
using Millo.Models;

namespace Millo.Controllers
{
    [RoutePrefix("Values")]
    public class ValuesController : ApiController
    {
        [HttpGet, Route("GetValues", Name = "GetValues")]
        // GET: api/Values
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        [HttpGet,Route("Void")]
        public void ReturnVoid()
        {
            //throw new DeLoachAero.WebApi.RFC7807Exception(new DeLoachAero.WebApi.RFC7807ProblemDetail
            //{
            //    Type = new Uri("https://www.example.com/probs/out-of-credit"),
            //    Title = "you do not have enough credit",
            //    Status = (int)HttpStatusCode.Forbidden,
            //    Detail = "Your current balance is 30 , but it cost 50",
            //    Instance = new Uri("/account/12345/msgs/abc", UriKind.Relative),
            //    Extensions= new Dictionary<string, dynamic>{
            //        {"balance",30 },
            //        {"accounts", new string[]{"account/12345","account/4343"} }
            //    }
            //}) ;
        }

        [HttpGet, Route("ReturnObject")]
        public ComplexTypeDtos GetObject()
        {
            ComplexTypeDtos complexTypeDtos = new ComplexTypeDtos
            {
                Name = "Ashish Khatiwada",
                date = DateTime.Now,
                Id = 121,
                married = true,
                Address = "Gauradaha -3 Jhapa , Nepal"
            };
            throw new InvalidOperationException("Hi ashish I can't pass you through this because this is all i have got");
            return complexTypeDtos;
        }
        [HttpGet, Route("GetUserApiKey", Name = "GetUserApiKey")]
        [Authorize]
        // GET: api/Values
        public IEnumerable<string> GetUserApiKey()
        {
            string apikey = "";
            if (!string.IsNullOrEmpty(HttpRequestMessageApiKeyExtension.GetApiKey(this.Request)))
            {
                apikey = HttpRequestMessageApiKeyExtension.GetApiKey(this.Request).ToString();
            }

            return new string[] { "value1", "value2", apikey };
        }
        [HttpGet, Route("GetUserIdentity", Name = "GetUserIdentity")]
        [Authorize]
        // GET: api/Values
        public IEnumerable<string> GetUserIdentity()
        {
            string apikey ="";
            if (!string.IsNullOrEmpty(HttpRequestMessageApiKeyExtension.GetApiKey(this.Request)))
            {
                apikey = HttpRequestMessageApiKeyExtension.GetApiKey(this.Request).ToString();
            }
            return new string[] { User.Identity.Name, User.Identity.AuthenticationType, User.Identity.IsAuthenticated.ToString(), User.IsInRole("admin").ToString() ,apikey.ToString()};
        }
        [HttpGet, Route("GetValue/{id:Range(1000,3000)}", Name = "GetValue")]
        // GET: api/Values/5
        public string Get(int id)
        {
            return "value";
        }
        [HttpGet, Route("getDifferentRoutes")]
        [ClientCacheControlFilter(ClientCacheControl.Public, 90000)]
        public IEnumerable<string> GetAll()
        {
            var getByIdUrl1 = Url.Link("GetValue", new { id = 2323 });

            var getByIdUrl = Url.Link("GetValues", null);
            var x = Request.GetSelfReferenceBaseUrl().ToString();
            var y = Request.RebaseUrlForClient(new Uri(getByIdUrl)).ToString();
            return new string[]
            {
                "generated from url.link = "+getByIdUrl,
                "base url that server believes = "+Request.GetSelfReferenceBaseUrl().ToString(),
                "Rebased url from the client prespective = "+Request.RebaseUrlForClient(new Uri(getByIdUrl)).ToString()
            };

        }

        [Route("PostValue")]
        // POST: api/Values
        public void Post([FromBody] string value)
        {
        }

        [Route("PutValue")]
        // PUT: api/Values/5
        public void Put(int id, [FromBody] string value)
        {
        }

        [Route("DeleteValue")]
        // DELETE: api/Values/5
        public void Delete(int id)
        {
        }
    }
}
