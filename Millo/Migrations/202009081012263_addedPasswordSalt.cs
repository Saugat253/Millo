namespace Millo.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class addedPasswordSalt : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "PrivateToken", c => c.String());
            AddColumn("dbo.Users", "PasswordSalt", c => c.String());
            DropColumn("dbo.Users", "PrivateTokenPass");
        }
        
        public override void Down()
        {
            AddColumn("dbo.Users", "PrivateTokenPass", c => c.String());
            DropColumn("dbo.Users", "PasswordSalt");
            DropColumn("dbo.Users", "PrivateToken");
        }
    }
}
