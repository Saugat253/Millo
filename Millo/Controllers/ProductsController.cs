using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Millo.Filters.AuthenticationFilter;

namespace Millo.Controllers
{
    [RoutePrefix("Products")]
    public class ProductsController : ApiController
    {
        [JsonConverter(typeof(StringEnumConverter))]
        public enum Names
        {
            Ashish,
            Milan,
            Saugat,
            Sandesh,
            Basanta
        }
        [JsonConverter(typeof(StringEnumConverter))]

        public enum toolbox
        {
            hammer,
            nail,
            screw,
            driller,
            wrench
        }
        [Route("GetProducts")]
        [ClientCacheControlFilter(ClientCacheControl.Public,5)]
        // GET: api/Products
        public IEnumerable<string> Get()
        {
            return new string[] { "Product1", "Product2" };
        }

        [Route("GetProduct")]
        [ClientCacheControlFilter(ClientCacheControl.Public, 5)]
        // GET: api/Products/5
        public string Get(int id)
        {
            return "Product1";
        }

        [HttpGet,Route("getProductsWithWidget/{values:enum(Millo.Controllers.ProductsController+Names)}", Name ="GetProducts")]
        [ClientCacheControlFilter(ClientCacheControl.Public, 5)]
        // POST: api/Products
        public string GetProducts(Names values)
        {
            string valuesReturned = "";
            valuesReturned = values.ToString();
            return valuesReturned;
        }

        [Route("PutProduct")]
        // PUT: api/Products/5
        public void Put(int id, [FromBody]string value)
        {
        }

        [Route("DeleteProduct")]
        // DELETE: api/Products/5
        public void Delete(int id)
        {
        }
    }
}
