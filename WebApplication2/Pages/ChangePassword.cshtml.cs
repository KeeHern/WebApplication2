using WebApplication2.ViewModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using WebApplication2.Model;
using WebApplication2.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace WebApplication2.Pages
{
    public class ChangePasswordModel : PageModel
    {
        public DbSet<AuditLogs> AuditLogss { get; set; }

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly IHttpContextAccessor _context;

        private readonly ILogger<ChangePasswordModel> _logger;

        private readonly AuthDbContext _dbcontext;



        [BindProperty]
        public ChangePassword CModel { get; set; }


        [BindProperty]
        public string ReCaptchaResponse { get; set; }



        public ChangePasswordModel(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDataProtectionProvider dataProtectionProvider,
         IHttpContextAccessor dbContext,
         ILogger<ChangePasswordModel> logger,
         AuthDbContext _dbcontext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger;
            this._dbcontext = _dbcontext;
        }



        public async Task<IActionResult> OnGet()
        {
            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                _logger.LogInformation("Session ID was not found. ");
                return RedirectToPage("Login");

            }


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
                _logger.LogInformation($"Your session has been timed out.");
                remove();

                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);

            }

            return Page();
        }


        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {

            // Inside your OnPostAsync method
            var recaptcha_SecretKey = "6Lf_xV4pAAAAAI3fQb53P9ZG6g-s8yGZZICKv_iU";
            var recaptcha_Api_Url = "https://www.google.com/recaptcha/api/siteverify";

            var recaptcha__Client = new HttpClient();
            var recaptchaResult = await recaptcha__Client.PostAsync(recaptcha_Api_Url, new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
                {
                new KeyValuePair<string, string>("secret", recaptcha_SecretKey),
                new KeyValuePair<string, string>("response", ReCaptchaResponse),
                new KeyValuePair<string, string>("remoteip", HttpContext.Connection.RemoteIpAddress.ToString())
            }));


            if (!recaptchaResult.IsSuccessStatusCode)
            {
                ModelState.AddModelError("", "reCAPTCHA failed to validate.");
                return Page();
            }

            var recaptcha_Content = await recaptchaResult.Content.ReadAsStringAsync();
            var recaptcha_Response = JsonConvert.DeserializeObject<Captcha>(recaptcha_Content);

            if (!recaptcha_Response.Success)
            {
                ModelState.AddModelError("", "reCAPTCHA failed to validate.");
                return Page();
            }



            if (CModel.Password != null && CModel.ConfirmPassword != null)
            {
                if (CModel.Password != null)
                {
                    if (!IsStrongPassword(CModel.Password))
                    {
                        ModelState.AddModelError(nameof(CModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                        return Page();
                    }
                }


                try
                {
                    var password_protector = dataProtectionProvider.CreateProtector("Password");
                    var ProtectPassword = password_protector.Protect(CModel.Password);

                    var userEmail = DecryptEmail(_context.HttpContext.Session.GetString("User_Email"));
                    var login_usr = await userManager.FindByEmailAsync(userEmail);
                    _logger.LogInformation($"User {userEmail} is found");
                    var changePasswordResult = await userManager.ChangePasswordAsync(login_usr, CModel.CurrentPassword, CModel.Password);

                    if (changePasswordResult.Succeeded)
                    {

                        if (string.IsNullOrEmpty(userEmail))
                        {
                            _logger.LogInformation($"User email is invalid. Password update was unsuccessful.");
                            return RedirectToPage("/Error");
                        }
                        var allUsers = _dbcontext.Registers.ToList(); 
                        var user = allUsers.FirstOrDefault(u => DecryptEmail(u.Email) == userEmail);


                        if (user == null)
                        {
                            _logger.LogInformation($"{userEmail}'s password update was unsuccessful.");
                            return NotFound();  

                        }


                        _logger.LogInformation($"{userEmail}'s password was updated successfully");
                       await record();
                        user.Password = ProtectPassword;
                        user.ConfirmPassword = ProtectPassword;

                        await _dbcontext.SaveChangesAsync();

                        return RedirectToPage("/UserDetails");
                    }
                    else if (!changePasswordResult.Succeeded)
                    {
                        ModelState.AddModelError(nameof(CModel.CurrentPassword), "Your current password is invalid");
                        return Page();
                    }
                    else
                    {
                        if (!changePasswordResult.Succeeded)
                        {
                            foreach (var error in changePasswordResult.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }

                            return Page();
                        }

                    }
                }
                catch (Exception ex)
                {
                    _logger.LogInformation($"error in 208 lines");
                    return NotFound();

                }






            }
            return Page();
        }

        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailProtection");
            return protector.Unprotect(encryptedEmail);
        }

        private bool IsStrongPassword(string password)
        {

            return password.Length >= 12
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(ch => !char.IsLetterOrDigit(ch));
        }

        public async Task<IActionResult> remove()
        {
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage("/Login");
        }


        private async Task record()
        {
            // Log user activity to the database
            var auditLog = new AuditLogs
            {
                User_Id = HttpContext.Session.GetString("User_Email"),
                timing = DateTime.UtcNow,
                tasks = "ChangePassword"
            };

            _dbcontext.AuditLogs.Add(auditLog);
            await _dbcontext.SaveChangesAsync();
        }
    }
}
