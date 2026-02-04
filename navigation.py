# (c) 2026 Novixx Systems
# MIT License

navbar_html = '''
<nav class="navbar navbar-expand-lg container-fluid p-4 ">
<div class="container-fluid">
      <div class="main-logo">
        <a href="/dashboard"><h1 class="text-white">Novixx Exchange</h1></a>
        </div>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <a class="nav-link text-white" href="/dashboard">Dashboard</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="/topup">Top Up</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="/withdraw">Withdraw</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="/trade">Trade</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link text-white" href="/logout">Logout</a>
                </li>
                <div class="nav-item dropdown">
            <a class="nav-link dropdown-toggle text-white" href="#" id="developerDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                Developer
            </a>
            <ul class="dropdown-menu" aria-labelledby="developerDropdown">
                <li><a class="dropdown-item" href="/addcoin">List Your Coin</a></li>
                <li><a class="dropdown-item" href="/api/price">API Documentation</a></li>
            </ul>
            </div>
            </ul>

        </div>
    </div>
</nav>
  <div id="billboard" class="padding-medium overflow-hidden">
    <div class="container">
'''