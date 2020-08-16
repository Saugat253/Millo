using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web;
using System.Web.Http.Routing;

namespace Millo.Constraints
{
    public class EnumerationConstraint : IHttpRouteConstraint
    {
        private Type _enum { get; set; }
        public EnumerationConstraint(string type)
        {
            var t = GetType(type);
            if (t == null || !t.IsEnum)
            {
                throw new ArgumentException("Argument type is not Enum");
            }
            _enum = t;
        }
        private static Type GetType(string typeName)
        {
            var t = Type.GetType(typeName);
            if (t != null)
            {
                return t;
            }
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
            {
                t = a.GetType(typeName);
                if (t != null)
                {
                    return t;
                }
            }
            return null;
        }
        public bool Match(HttpRequestMessage request, IHttpRoute route, string parameterName, IDictionary<string, object> values, HttpRouteDirection routeDirection)
        {
            object value1;
            if (values.TryGetValue(parameterName, out value1) && value1 != null)
            {
                var stringVal = value1 as string;
                if (!string.IsNullOrEmpty(stringVal))
                {
                    stringVal = stringVal.ToLower();

                    if (null != _enum.GetEnumNames().FirstOrDefault(a => a.ToLower().Equals(stringVal)))
                    {
                        return true;
                    }
                }

            }
            return false;
        }
    }
}