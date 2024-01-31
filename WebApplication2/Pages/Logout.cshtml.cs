using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using WebApplication2.ViewModel;
using Microsoft.EntityFrameworkCore;
using WebApplication2.Model;
using System;
using System.Threading.Tasks;

namespace WebApplication2.Pages
{
    public class LogoutModel : PageModel
    {
        private SignInManager<IdentityUser> signInManager { get; }
        private readonly AuthDbContext _dbcontext;
        private readonly IHttpContextAccessor _context;
        private readonly ILogger<ChangePasswordModel> _logger;

        public LogoutModel(IHttpContextAccessor context,
            SignInManager<IdentityUser> signInManager,
            AuthDbContext _dbcontext,
            ILogger<ChangePasswordModel> logger)
        {
            _context = context;
            this.signInManager = signInManager;
            this._dbcontext = _dbcontext;
            _logger = logger;
        }

        public async Task<IActionResult> OnGet()
        {

            if (_context?.HttpContext != null)
            {
                string userEmail = _context.HttpContext.Session.GetString("User_Email");

                if (!string.IsNullOrEmpty(userEmail))
                {
                    await remove(userEmail);

                    _context.HttpContext.Session.Clear();

                    foreach (var key in _context.HttpContext.Session.Keys)
                    {
                        _context.HttpContext.Session.Remove(key);
                    }

                    return RedirectToPage("/Login");
                }
            }
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("Session cannot found in logout");
            return RedirectToPage("/login");
        }

        public async Task<IActionResult> remove(string userEmail)
        {
            try
            {
                _logger.LogInformation("Logout successfully:");
                var auditLog = new AuditLogs
                {
                    User_Id = userEmail,
                    timing = DateTime.UtcNow,
                    tasks = "Logout"
                };

                _dbcontext.AuditLogs.Add(auditLog);
                await _dbcontext.SaveChangesAsync();

                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToPage("/Login");
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error has occurred: {ex}");
                throw;
            }
        }
    }
}
