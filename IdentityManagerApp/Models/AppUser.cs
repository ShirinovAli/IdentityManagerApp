using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManagerApp.Models
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }
        [NotMapped]
        public int RoleId { get; set; }
        [NotMapped]
        public string Role { get; set; }
    }
}
