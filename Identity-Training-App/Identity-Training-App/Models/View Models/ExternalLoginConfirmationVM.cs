using System.ComponentModel.DataAnnotations;

namespace Identity_Training_App.Models.View_Models
{
    public class ExternalLoginConfirmationVM
    {
        [EmailAddress]
        [Required]
        public string Email { get; set; }

        [Required]
        public string Name { get; set; }
    }
}
