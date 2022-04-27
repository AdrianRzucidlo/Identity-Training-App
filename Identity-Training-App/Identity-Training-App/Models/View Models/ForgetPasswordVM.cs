using System.ComponentModel.DataAnnotations;

namespace Identity_Training_App.Models.View_Models
{
    public class ForgetPasswordVM
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
