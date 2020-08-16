using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace Millo.Controllers
{
    [RoutePrefix("exception")]
    public class ExceptionController : ApiController
    {

        // GET: api/Exception
        [HttpGet,Route("")]
        public IEnumerable<string> Get()
        {
            throw new NotImplementedException();
            return new string[] { "value1", "value2" };
        }

        // GET: api/Exception/5
        public string Get(int id)
        {
            throw new ArgumentOutOfRangeException();
            return "value";
        }

        // POST: api/Exception
        public void Post([FromBody]string value)
        {
        }

        // PUT: api/Exception/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE: api/Exception/5
        public void Delete(int id)
        {
        }
    }
}
