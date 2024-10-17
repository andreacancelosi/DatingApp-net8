using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

//nella classe AccountController
public class AccountController(DataContext context) : BaseApiController
{
        //end point su dove atterra
    [HttpPost("register")] //account/register
    public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto)
    {

        //richiamo della funzione privata UserExists e restituisce una bedrequest n testo.
        if(await UserExists(registerDto.Username)) return BadRequest("Username preso!");

        using var hmac = new HMACSHA512();

        var user = new AppUser
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return user;
    }

    //Una funzione privata che permette di controllare se il nome esiste nel
    // database context nella tabella Users prende tutti i dati con Any e poi
    // con la lammbda expression confronta i valore che sono all'interno di UserName con "username"
    // che gli viene dato.
    private async Task<bool> UserExists(string username)
    {
        return await context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());
    }
}
