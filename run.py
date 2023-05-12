from app import create_app
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain("cert.pem", "key.pem")
app = create_app()

if __name__ == "__main__":
    app.run(ssl_context=context, debug=True)
