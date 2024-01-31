using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using WebApplication2.Model;
using WebApplication2.Pages;
using WebApplication2.ViewModels;
using WebApplication2.ViewModel;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace WebApplication2.Pages
{
    public class UserDetailsModel : PageModel
    {

        private readonly IHttpContextAccessor _context;
        private readonly ILogger<UserDetailsModel> _logger;
        private readonly AuthDbContext _dbcontext;

        private SignInManager<IdentityUser> signInManager { get; }

        public UserDetailsModel(
           IHttpContextAccessor dbContext,
           ILogger<UserDetailsModel> logger,
           SignInManager<IdentityUser> signInManager,
           AuthDbContext _dbcontext
)
        {
            this._context = dbContext;
            this._logger = logger;
            this.signInManager = signInManager;
            this._dbcontext = _dbcontext;
        }


        public async Task<IActionResult> OnGet() 
        {

            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                _logger.LogInformation("Your session ID could not be found");
                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToPage("Login");

            }
            var auditLog = new AuditLogs
            {
                User_Id =_context.HttpContext.Session.GetString("User_Email"),
                timing = DateTime.UtcNow,
                tasks = "User Detail"
            };

            _dbcontext.AuditLogs.Add(auditLog);
            await _dbcontext.SaveChangesAsync();
           

            var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"time: {sessionTimeoutSeconds}");

            var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

            if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
            {

                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                _logger.LogInformation($"Your session has been timed out");
                remove();
                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);
            }

            var userEmail = _context.HttpContext.Session.GetString("User_Email");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            return Page();
        }



        public async Task<IActionResult> remove()
        {
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage("/Login");
        }
    }
}

