using IdentityJWTDemo.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityJWTDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class BookApiController(
    ApplicationDbContext dbContext
) : ControllerBase
{
    private readonly ApplicationDbContext _dbContext = dbContext;
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult<IEnumerable<Book>>> GetBooks()
    {
        return Ok(await _dbContext.Books.ToListAsync());
    }

    [HttpGet("{id}")]
    [AllowAnonymous]
    public async Task<ActionResult<Book>> GetBook(int id)
    {
        var book = await _dbContext.Books.FirstOrDefaultAsync(b => b.Id == id);
        if (book == null)
        {
            return NotFound();
        }
        return Ok(book);
    }
    [HttpPost]
    public async Task<ActionResult<Book>> CreateBook(BookParameter parameter)
    {
        var book = new Book
        {
            Title = parameter.Title
        };
        _dbContext.Books.Add(book);
        await _dbContext.SaveChangesAsync();
        return CreatedAtAction(nameof(GetBook), new { id = book.Id }, book);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateBook(int id, Book updatedBook)
    {
        var book = await _dbContext.Books.FirstOrDefaultAsync(b => b.Id == id);
        if (book == null)
            return NotFound();

        book.Title = updatedBook.Title;
        await _dbContext.SaveChangesAsync();
        return Ok();
    }

    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteBookAsync(int id)
    {
        var book = await _dbContext.Books.FirstOrDefaultAsync(b => b.Id == id);

        if (book == null)
            return NotFound();

        _dbContext.Books.Remove(book);
        await _dbContext.SaveChangesAsync();
        return Ok();
    }
}

