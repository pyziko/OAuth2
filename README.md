"# OAuth2" 

1. g can only be used in a request context, else it won't work
2. every request has its own g. hence does not keep its content when moving to another request

# we use g to pass access_token to   @github.tokengetter in oa for cleaner code
then we can localhost:5000/login/github  to fetch username

then in the GithubLoginResource
after retrieving the username, we can save it to our db WITHOUT A PASSWORD and generate a token for them to be able to
then access our app resources


What if user wants to login with username and password
see impl in SetPassword in user resources

hence with the above, we can choose to login with github, then set our password
then login with our github username and new password

#####NOTE
url_for("github.authorize", _external=True) is same as
#callback="http://localhost:5000/login/github/authorized"

But advantage
USING
    #  external is for full url building
    # our internal remains /login/github/authorized
    # while external http://localhost:5000/login/github/authorized
    # hence if ip changes no need for hardcoding


HASHING PASSWORD. INCASE USER sets password
OR REGISTERS WITH PASSWORD
 Use bcrpyt hashing checkout bc, user under resources for implementation