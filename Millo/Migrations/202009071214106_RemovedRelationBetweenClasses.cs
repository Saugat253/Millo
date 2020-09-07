namespace Millo.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class RemovedRelationBetweenClasses : DbMigration
    {
        public override void Up()
        {
            DropForeignKey("dbo.UserRoles", "User_UserId", "dbo.Users");
            DropForeignKey("dbo.UserRoles", "Role_Id", "dbo.Roles");
            DropIndex("dbo.UserRoles", new[] { "User_UserId" });
            DropIndex("dbo.UserRoles", new[] { "Role_Id" });
            AddColumn("dbo.Users", "Role_Id", c => c.String(maxLength: 128));
            CreateIndex("dbo.Users", "Role_Id");
            AddForeignKey("dbo.Users", "Role_Id", "dbo.Roles", "Id");
            DropColumn("dbo.Users", "Phone");
            DropTable("dbo.UserRoles");
        }
        
        public override void Down()
        {
            CreateTable(
                "dbo.UserRoles",
                c => new
                    {
                        User_UserId = c.Int(nullable: false),
                        Role_Id = c.String(nullable: false, maxLength: 128),
                    })
                .PrimaryKey(t => new { t.User_UserId, t.Role_Id });
            
            AddColumn("dbo.Users", "Phone", c => c.Int(nullable: false));
            DropForeignKey("dbo.Users", "Role_Id", "dbo.Roles");
            DropIndex("dbo.Users", new[] { "Role_Id" });
            DropColumn("dbo.Users", "Role_Id");
            CreateIndex("dbo.UserRoles", "Role_Id");
            CreateIndex("dbo.UserRoles", "User_UserId");
            AddForeignKey("dbo.UserRoles", "Role_Id", "dbo.Roles", "Id", cascadeDelete: true);
            AddForeignKey("dbo.UserRoles", "User_UserId", "dbo.Users", "UserId", cascadeDelete: true);
        }
    }
}
