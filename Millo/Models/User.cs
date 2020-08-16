using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Data.SqlTypes;
using System.Linq;
using System.Web;

namespace Millo.Models
{
    public class User : DbContext
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string PrivateTokenPass { get; set; }
        public string PublicToken { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullAddress { get; set; }

        [Phone]
        public int  Phone { get; set; }

        public string City { get; set; }
        public string Country { get; set; }
        public string Street { get; set; }
        public DateTime RegistrationDate { get; set; }
        public DateTime BirthDate { get; set; }
        public bool IsActive { get; set; }



    }
    public class ProfilePic : DbContext
    {
        public int ProfilePicId { get; set; }
        public string Location { get; set; }
        public string Status { get; set; }
        public int likes { get; set; }
        public int Love { get; set; }
        public int Haha { get; set; }
        public int Angry { get; set; }
        public int Wow { get; set; }
        public int Comments { get; set; }
    }
}