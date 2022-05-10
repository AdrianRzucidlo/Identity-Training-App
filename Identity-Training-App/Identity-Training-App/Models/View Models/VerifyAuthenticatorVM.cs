using System.ComponentModel.DataAnnotations;

namespace Identity_Training_App.Models.View_Models
{
    public class VerifyAuthenticatorVM
    {
        [Required]
        public  string Code { get; set; }

        public string ReturnUrl { get; set; }
        [Display(Name ="Remember me?")]
        public bool RememberMe { get; set; }
    }
}
