<?php require_once 'db.php';
$stmt = $pdo->query("SELECT * FROM produits ORDER BY nom");
$produits = $stmt->fetchAll();


// Création d'un cookie signé
function createSignedCookie($name, $value, $secretKey)
{
    // Créer une signature HMAC
    $signature = hash_hmac('sha256', $value, $secretKey);

    // Combiner valeur + signature
    $signedValue = $value . '.' . $signature;

    setcookie($name, $signedValue, [
        'expires' => time() + 3600,
        'httponly' => true,
        'secure' => true,
        'samesite' => 'Strict'
    ]);
}

// Vérification du cookie
function verifySignedCookie($name, $secretKey)
{
    if (!isset($_COOKIE[$name])) {
        return false;
    }

    // Séparer valeur et signature
    $parts = explode('.', $_COOKIE[$name], 2);

    if (count($parts) !== 2) {
        return false; // Cookie invalide
    }

    list($value, $signature) = $parts;

    // Recalculer la signature
    $expectedSignature = hash_hmac('sha256', $value, $secretKey);

    // Comparaison sécurisée (protection timing attack)
    if (hash_equals($expectedSignature, $signature)) {
        return $value; // Cookie valide
    }

    return false; // Cookie modifié !
}

// Utilisation
$secretKey = 'votre_cle_secrete_tres_longue_et_aleatoire';
createSignedCookie('user_role', 'admin', $secretKey);

// Plus tard...
$role = verifySignedCookie('user_role', $secretKey);
if ($role === false) {
    die('Cookie modifié ou invalide !');
}

function encryptCookie($name, $value, $key)
{
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv);

    // Combiner IV + données chiffrées
    $cookieValue = base64_encode($iv . $encrypted);

    setcookie($name, $cookieValue, [
        'httponly' => true,
        'secure' => true
    ]);
}

function decryptCookie($name, $key)
{
    if (!isset($_COOKIE[$name])) {
        return false;
    }

    $data = base64_decode($_COOKIE[$name]);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);

    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}

// Dans le cookie : seulement un ID de session aléatoire
session_start();
$_SESSION['user_role'] = 'admin';
$_SESSION['user_id'] = 123;

?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Magasin - TP Cookies</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
</head>

<body class="bg-light">
    <div class="container py-5">
        <h1 class="mb-4"><i class="bi bi-shop me-2"></i>
            Magasin en ligne
        </h1>
        <div class="alert alert-info">
            <i class="bi bi-cookie me-2"></i>
            Ce site utilise des <strong>cookies</strong> pour conserver votre panier même si vous fermez le navigateur !
        </div>

        <div class="text-end mb-3">
            <a href="panier.php" class="btn btn-primary btn-lg">
                <i class="bi bi-cart4 me-2"></i> Voir mon panier
            </a>
        </div>

        <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
            <?php foreach (isset($produits) ? $produits : [] as $p): ?>
                <div class="col">
                    <div class="card h-100 shadow-sm">
                        <div class="card-body d-flex flex-column">
                            <h5 class="card-title"><?= htmlspecialchars($p['nom']) ?></h5>
                            <p class="card-text mt-auto">
                                <strong class="text-success fs-4"><?= number_format($p['prix'], 2) ?> €</strong>
                            </p>
                            <form method="post" action="ajouter.php" class="mt-3">
                                <input type="hidden" name="id" value="<?= $p['id'] ?>">
                                <input type="hidden" name="nom" value="<?= htmlspecialchars($p['nom']) ?>">
                                <input type="hidden" name="prix" value="<?= $p['prix'] ?>">
                                <button type="submit" class="btn btn-success w-100">
                                    <i class="bi bi-cart-plus me-2"></i> Ajouter au panier
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <hr class="my-5">
        <p class="text-center">
            <a href="vider.php" class="btn btn-outline-danger"><i class="bi bi-trash"></i> Vider le panier</a>
            <a href="vider.php?demo_expire=1" class="btn btn-outline-warning ms-3">
                <i class="bi bi-clock"></i> Démo expiration (30 s)
            </a>
        </p>
    </div>
</body>

</html>