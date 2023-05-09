<?php

// Générer une chaîne de sel aléatoire de longueur variable contenant des chiffres et des lettres
function generateStrings($min_length, $max_length)
{
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; // Chiffres et lettres autorisés
    $characters_length = strlen($characters);

    for ($i = $min_length; $i <= $max_length; $i++) {
        $combinations = pow($characters_length, $i); // Nombre total de combinaisons

        for ($j = 0; $j < $combinations; $j++) {
            $string = '';
            $index = $j;

            // Convertir l'index en base $characters_length pour générer une chaîne de caractères unique
            for ($k = 0; $k < $i; $k++) {
                $string .= $characters[$index % $characters_length];
                $index = floor($index / $characters_length);
            }

            yield $string;
        }
    }
}

foreach (generateStrings(1, 20)  as $salt) {
    // Concaténation du secret avec le sel
    $secret = "9be4a60f645f" . $salt;

    // Calcul du hash
    $hash = hash('fnv164', ($secret));

    // Vérification que le hash commence par '0e' suivi de chiffres
    if (preg_match('/^0e\d+$/', $hash)) {
        echo "Salt: $salt, Le hash $hash commence par '0e' suivi de chiffres.\n";
    }
}
