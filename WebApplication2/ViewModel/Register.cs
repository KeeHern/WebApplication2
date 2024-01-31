using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication2.ViewModels
{
    public class Register
    {
        [Key]
        public int UserId { get; set; }

        [Required(ErrorMessage = "First name is required")]
        public string First_Name { get; set; }

        [Required(ErrorMessage = "Last name is required")]
        public string Last_Name { get; set; }

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; }

        [Required(ErrorMessage = "NRIC is required")]
        public string NRIC { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Confirm password is required")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Your password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Date of birth is required")]
        [DataType(DataType.Date)]
        public DateTime DOB { get; set; }
        public string? ResumeFilePath { get; set; }

        [Required(ErrorMessage = "WhoAmI is required")]
        public string WhoAmI { get; set; }
    }
}
