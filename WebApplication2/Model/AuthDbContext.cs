using WebApplication2.ViewModel;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApplication2.ViewModels;

namespace WebApplication2.Model
{



    public class AuthDbContext : IdentityDbContext
    {
        private readonly IConfiguration _configuration;

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString"); optionsBuilder.UseSqlServer(connectionString);
        }

        public DbSet<AuditLogs> AuditLogs { get; set; }

        public DbSet<Register> Registers { get; set; }

    }




}
