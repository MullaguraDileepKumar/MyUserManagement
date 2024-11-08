using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserManagement.Core.Entities;

namespace UserManagement.Core.DbContext
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }
        public DbSet<Log> Logs { get; set; }
        public DbSet<Message> Messages { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(e =>
            {
                e.ToTable("Users");
            });
            builder.Entity<IdentityUserClaim<string>>(e =>
            {
                e.ToTable("UserClaim");
            });
            builder.Entity<IdentityUserLogin<string>>(e =>
            {
                e.ToTable("UserLogin");
            });
            builder.Entity<IdentityUserToken<string>>(e =>
            {
                e.ToTable("UserToken");
            });
            builder.Entity<IdentityRole<string>>(e =>
            {
                e.ToTable("Role");
            });
            builder.Entity<IdentityRoleClaim<string>>(e =>
            {
                e.ToTable("RoleClaims");
            });
            builder.Entity<IdentityUserRole<string>>(e =>
            {
                e.ToTable("UserRoles");
            });
        }

    }
}
