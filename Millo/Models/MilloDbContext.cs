using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Web;

namespace Millo.Models
{
    public partial class MilloDbContext : DbContext
    {

        public MilloDbContext()
            : base("name=MilloDbContext")
        {
        }

        //protected override void OnModelCreating(DbModelBuilder modelBuilder)
        //{
        //    throw new UnintentionalCodeFirstException();
        //}
        
        public  DbSet<Role> Roles { get; set; }
        public  DbSet<UserClaim> UserClaims { get; set; }
        public  DbSet<UserLogin> UserLogins { get; set; }
        public  DbSet<User> Users { get; set; }
    }
}
