using WebApplication2.ViewModel;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO; 
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WebApplication2.Model;
using WebApplication2.ViewModels;
using static System.Net.WebRequestMethods;

namespace WebApplication2.Pages
{
	public class RegisterModel : PageModel
	{

		private UserManager<IdentityUser> userManager { get; }
		private SignInManager<IdentityUser> signInManager { get; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly AuthDbContext _context; 

        private readonly ILogger<RegisterModel> _logger;



        [BindProperty]
		public Register RModel { get; set; }

        [BindProperty]
        public IFormFile Resume { get; set; }

        public RegisterModel(
           UserManager<IdentityUser> userManager,
           SignInManager<IdentityUser> signInManager,
           IDataProtectionProvider dataProtectionProvider,
            AuthDbContext dbContext,
            ILogger<RegisterModel> logger)
        { 
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger; 

        }



        public void OnGet()
		{
		}



        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            var file_name = "";

            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$");
            if (RModel.Email == null || !emailRegex.IsMatch(RModel.Email))
            {
                ModelState.AddModelError(nameof(RModel.Email), "Please enter a valid email.");
                return Page();
            }



            if (RModel.First_Name != null && RModel.Last_Name != null && RModel.NRIC != null)
            {

                var Name_protector = dataProtectionProvider.CreateProtector("Name");

                var protectFirst_Name = Name_protector.Protect(RModel.First_Name.ToLower());
                var protectLast_Name = Name_protector.Protect(RModel.Last_Name.ToLower());

                var Email_protector = dataProtectionProvider.CreateProtector("EmailProtection");
                var email_Regex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
       
                if (RModel.Email == null || !email_Regex.IsMatch(RModel.Email))
                {
                    ModelState.AddModelError(nameof(RModel.Email), "Please enter a valid email.");
                    return Page();
                }

                var protectEmail = Email_protector.Protect(RModel.Email.ToLower());
                var nricRegex = new Regex(@"^[TtSs]\d{7}[A-Za-z]$");
                if (RModel.NRIC == null || !nricRegex.IsMatch(RModel.NRIC))
                {
                    ModelState.AddModelError(nameof(RModel.NRIC), "Please enter a valid NRIC.");
                    return Page();
                }

                var IC_protector = dataProtectionProvider.CreateProtector("NRIC");
                var ProtectNRIC = IC_protector.Protect(RModel.NRIC);


                var all_email = await _context.Registers.ToListAsync();
                var existingUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == RModel.Email);
                var existingUser_register_db = all_email.FirstOrDefault(u => DecryptEmail(u.Email).ToLower() == RModel.Email.ToLower());



            if ( existingUser !=null)
            {
                ModelState.AddModelError(nameof(RModel.Email), "Email already been used");
                return Page();
            }
            

            if (RModel.Password != null){
                if (!IsStrongPassword(RModel.Password))
                {
                    ModelState.AddModelError(nameof(RModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                    return Page();
                }
            }
            if (Resume != null)
            {
                    long maxFileSizeInBytes = 10 * 1024 * 1024;

                    if (Resume.Length > maxFileSizeInBytes)
                    {
                        ModelState.AddModelError(nameof(Resume), "File size exceeds the allowed limit.");
                        return Page();
                    }
                  string[] allowedExtensions = { ".pdf", ".doc", ".docx" }; // Add the allowed extensions
                var fileExtension = Path.GetExtension(Resume.FileName).ToLowerInvariant();
                if (!allowedExtensions.Contains(fileExtension))
                {
                    ModelState.AddModelError(nameof(Resume), "Invalid file extension. Only .pdf, .doc, .docx extensions are allowed");
                    return Page();
                }
                else
                {
                    file_name = GenerateRandomNumber(fileExtension);


                    var File_Path = file_name;



                    using (var File_Stresm = new FileStream(File_Path, FileMode.Create))
                    {
                        await Resume.CopyToAsync(File_Stresm);
                    }
                }

            }

              if(RModel.Password == null)
                {
                    ModelState.AddModelError(nameof(RModel.Password), "Password is required.");
                    return Page();
                }
               var password_protector = dataProtectionProvider.CreateProtector("Password");
               var ProtectPassword = password_protector.Protect(RModel.Password);


                if (ModelState.IsValid)
                {
                    var user = new IdentityUser()
                    {
                        UserName = RModel.Email,
                        Email = RModel.Email
                    };


                    if (!string.IsNullOrEmpty(RModel.WhoAmI))
                    {
                        // Encode "<" and ">"
                        RModel.WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RModel.WhoAmI);
                    }


                    var register = new Register()
                    {
                        Email = protectEmail,
                        First_Name = protectFirst_Name,
                        Last_Name = protectLast_Name,
                        DOB = RModel.DOB,
                        ConfirmPassword = ProtectPassword,
                        Password = ProtectPassword,
                        NRIC = ProtectNRIC,
                        Gender = RModel.Gender,
                        WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RModel.WhoAmI),
                        ResumeFilePath = file_name, // Set the ResumeFilePath property
                    };



                    // // Assuming db context is available
                    _context.Registers.Add(register);
                    var result1 = await _context.SaveChangesAsync();

                    var result = await userManager.CreateAsync(user, RModel.Password);

                    if (result1 > 0 && result.Succeeded) // Check if any changes were saved
                    {
                        await signInManager.SignInAsync(user, false);
                        return RedirectToPage("Index");
                    }
                    else
                    {
                        // Handle the case where no changes were saved
                        ModelState.AddModelError("", "There was an error in saving the data.");
                        return Page();
                    }
                }



            
        }

    return Page();



}




        private string GenerateRandomNumber(string fileExtension)
        {
            var random = new Random();
            var randomNumber = random.Next(1, 10001);
            var filePath = Path.Combine(".\\resume", randomNumber + fileExtension);

            if (System.IO.File.Exists(filePath))
            {
                return GenerateRandomNumber(fileExtension);
            }
            else
            {
                return filePath;
            }
        }


        private string DecryptEmail(string encryptedEmail)
        {
            // Use the appropriate decryption logic here
            var protector = dataProtectionProvider.CreateProtector("EmailProtection");
            return protector.Unprotect(encryptedEmail);
        }

        // validate the password, return boolean
        private bool IsStrongPassword(string password)
        {
            
            return password.Length >= 12
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(ch => !char.IsLetterOrDigit(ch));
        }



       
       





    }
}
