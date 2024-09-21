import click
from pixher_code import file_to_png_with_aes, png_to_file_with_aes, password_input

@click.group(help="Pixher: A tool to encrypt files into PNG images and decrypt them back.")
def cli():
    pass

@click.command(short_help="Encrypt a file into a PNG image", help="Encrypt the FILE into a PNG image. \n\nUsage: encrypt <file>")
@click.argument('file', type=click.Path(exists=True))
def encrypt(file):
    """Encrypt the FILE into a PNG image."""
    password = password_input("Enter a strong password: ")
    confirm_password = password_input("Confirm password: ")

    if password != confirm_password:
        click.echo("Error: Passwords do not match.")
        return

    output_image = file_to_png_with_aes(file, password)
    click.echo(f"File successfully encrypted and saved as PNG: {output_image}")

@click.command(short_help="Decrypt a PNG image", help="Decrypt the PNG image back to its original file. \n\nUsage: decrypt or <image>")
@click.argument('image', type=click.Path(exists=True))
def decrypt(image):
    """Decrypt the PNG image back to the original file."""
    password = password_input("Enter the password for decryption: ")

    original_file = png_to_file_with_aes(image, password)
    click.echo(f"Decrypted successfully to file: {original_file}")

@click.command(short_help="About Pixher", help="Show information about the tool and how to use it. \n\nUsage: about")
def about():
    """Display information about Pixher tool."""
    click.echo("Pixher: A tool that allows you to encrypt files into PNG images and decrypt them back.\n")
    click.echo("Usage examples:")
    click.echo("  pixher encrypt <file>      Encrypt a file into a PNG image")
    click.echo("  pixher decrypt <image>     Decrypt a PNG image back into the original file")
    click.echo("\nEnsure you remember your password as it's required for both encryption and decryption.")

# Adding commands to the CLI with aliases
cli.add_command(encrypt, name='encrypt')
cli.add_command(decrypt, name='decrypt')
cli.add_command(about, name='about')

if __name__ == "__main__":
    cli()
