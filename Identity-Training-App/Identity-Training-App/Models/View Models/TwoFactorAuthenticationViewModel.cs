using System.ComponentModel.DataAnnotations;

namespace Identity_Training_App.Models.View_Models
{
    public class TwoFactorAuthenticationViewModel
    {
        //to login
        [Required]
        public string Code { get; set; }
        //to register
        public string Token { get; set; }

        public string QRCodeUrl { get; set; }
    }
}
