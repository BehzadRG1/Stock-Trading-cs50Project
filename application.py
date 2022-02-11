import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # return apology("TODO")

    # with user id we have access to a users's transactions

    user_id = session["user_id"]

    # we need to show this informations in our page (from transactions table we create in SQL in buy section) : symbol, name (of company), shares, price, type (buy or sell), total price.
    # Also display the user’s current cash balance along with a grand total (from cs50 website)
    # use '[0]["cash"]' because this syntax return a dictionary to us with a key and a value and we just need the value.

    items = db.execute("SELECT symbol, name, price, SUM(shares), type FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # calculate grand total (cash + stocks’ total value).

    totalCash = cash

    for item in items:
        totalCash += item["price"] * item["SUM(shares)"]

    # get this values from html codes then update and show them. use same name for each one.

    return render_template("index.html", items=items, cash=usd(cash), usd=usd, total=totalCash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # return apology("TODO")

    # with user_id from users data base, we have access to a user's information.
    # we need to create a table (transactions) in finance.db.
    # use SQL in finance.db and use SQL's syntaxes to create a table.
    # in this table we need this values (as saying in cs50 website in buy and history section): id, user_id, name, shares, price, type (sell or buy), symbol, time (date and time).

    # here first check the method (get or post).

    if (request.method == "GET"):
        return render_template("buy.html")
    else:
        # check what symbol the user wants to buy. get the input value from html page using 'request.form.get'
        # uppercase the value because every symbols is showed in uppercase (like 'NFLX' that showed in cs50 website)

        symbol = request.form.get("symbol").upper()

        # Render an apology if the input is blank or the symbol does not exist (as per the return value of lookup). text from cs50 website.
        inputed = lookup(symbol)

        if not symbol:
            return apology("please enter a symbol")
        elif not inputed:
            return apology("symbol is not valid!!")

        # Render an apology if the input is not a positive integer.
        # try/except method try to convert the input to an integer and if input value was not a number, it can't convert that and return an apology.
        # also check if input is positive number or not.
        try:
            share = int(request.form.get("shares"))
        except:
            return apology("please enter a positive number of shares!")

        if share <= 0:
            return apology("please enter a positive number of shares!")

        # Query database for users id and see how much cash does they already have
        # use '[0]["cash"]' because this syntax return a dictionary to us with a key and a value and we just need the value.

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']

        # calculate total price of inputed symbol shares
        name = inputed["name"]
        price = inputed["price"]
        totalPrice = price * share

        # then check if user can buy the shares

        if cash < totalPrice:
            return apology("sorry, you can't afford the number of shares at the current price.")

        # Once you’ve implemented buy correctly, you should be able to see users’ purchases in your new table (from cs50 website)
        # also check remain cash after buy shares and update it in our table in SQL.
        # also update other values (information) of user after buy proccess completed.
        else:
            remainCash = cash - totalPrice
            db.execute("UPDATE users SET cash = ? WHERE id = ?", remainCash, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       user_id, name, share, price, 'buy', symbol)

        return redirect('/')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # return apology("TODO")

    # here we just need a table that show the history of each user transactions to them.
    # so we just need some information from transactions table from SQL data base and send them to html codes.

    user_id = session["user_id"]
    items = db.execute("SELECT symbol, price, shares, type, time FROM transactions WHERE user_id = ?", user_id)

    return render_template("history.html", items=items, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # return apology("TODO")

    # first check the method (get or post).

    if (request.method == "GET"):
        return render_template("quote.html")
    else:
        # check what symbol the user is looking for. get the input value from html page using 'request.form.get'

        symbol = request.form.get("symbol")

        if not symbol:
            return apology("please enter a symbol!!")

        # use lookup function (from helpers.py) for check if user inputed symbol is valid or not
        # use usd function (from helpers.py) for show the formated price

        inputSymbol = lookup(symbol)

        if not inputSymbol:
            return apology("symbol is not valid!!")

        return render_template("quoted.html", inputSymbol=inputSymbol, usd=usd)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # return apology("TODO")

    # first check the method (get or post)

    if (request.method == "GET"):
        return render_template("register.html")
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Require that a user input a username, Render an apology if the user’s input is blank or the username already exists.
        # also do this for check password and it's confirmation is entered or not

        if not username:
            return apology('please enter your username!!')
        elif not password:
            return apology('please enter your password!!')
        elif not confirmation or password != confirmation:
            return apology('please confirm your password!! This field must be exactly like your password.')

        # Add users to users data base and storing a hash of the user’s password (use generate_password_hash Hash the user’s password and usedb.execute for insert the new user)
        # also check if username is already exists, show an apology

        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            # use this to back to home page after user registered
            return redirect("/")
        except:
            return apology('This username is already exists!!')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # return apology("TODO")

    if (request.method == "GET"):
        # Query database for users id and see what symbol does they already have
        # then groupe them by symbol because we don't want to have a symbol more than once in our select option.

        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("sell.html", symbols=symbols)
    else:
        # check that which user wants to sell shares
        # check what symbol and how many shares user wants to sell by get values of inputed from html codes (select -> options)

        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Render an apology if the input is not a positive integer

        if shares <= 0:
            return apology("please enter a positive number of shares!")

        # use lookup function (from helpers.py) for check the price and the name of our stock.
        # then fill every fields of transactions table with them.
        # calculate the total price of shares that the user wants to sell.

        item_price = lookup(symbol)["price"]
        item_name = lookup(symbol)["name"]
        sellPrice = shares * item_price

        # use '[0]["shares"]' because this syntax return a dictionary to us with a key and a value and we just need the value.
        # check user's current shares from transactions table in SQL.

        ownedShares = db.execute(
            "SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]

        # if the user does not own that many shares of the stock render an apology

        if ownedShares < shares:
            return apology("sorry, you don't have enough shares!!")

        # check user's current cash from users table in SQL and update that after sell proccess complete.
        # also update other values (information) of user after sell proccess completed.

        currentCash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", currentCash + sellPrice, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",
                   user_id, item_name, -shares, item_price, "sell", symbol)

        # return to home page after sell proccess completed.

        return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
