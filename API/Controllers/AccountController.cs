using System;
using System.Reflection.Metadata.Ecma335;
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
    
    //creo un metodo pubblico che mi permette di registrare l'utente
    //Actionresult è la procedura di azione che voglio utilizzare sul modello AppUser
    //"Register" è il nome che dò al mio metodo posso mettere anche un nome casuale
    //all'interno delle tonde sono le variabili che voglio acquisire - ovvero quelle che si aspetta
    // prese dalla classe RegisterDto e un nuove identificativo "registerDto"
        public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto)
    {

        //richiamo della funzione privata UserExists e restituisce una bedrequest n testo.
        if(await UserExists(registerDto.Username)) return BadRequest("Username preso!");

        //usare la variabile hmac per implementare la funzione HMA..... per poi utlizzarla per creare la password 
        using var hmac = new HMACSHA512();

        //crea un nuovo AppUser con gli elementi che lo compongono tipo username passwordhash e passwordsalt.
        var user = new AppUser
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        //Aggiunge al database la riga con le informazioni appena preso
        context.Users.Add(user);
        //Salva i cambiamenti al databse
        await context.SaveChangesAsync();

        return user;
    }

    [HttpPost("login")] //account/login
    public async Task<ActionResult<AppUser>> Login(LoginDto loginDto)
    {
        var user = await context.Users.FirstOrDefaultAsync(
            x => x.UserName.ToLower() == loginDto.Username.ToLower());

            if(user == null) return Unauthorized("Invalid username");

            if(user.PasswordHash == null) return Unauthorized("Password non inserita");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computeHash.Length; i++)
            {
                if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }

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
