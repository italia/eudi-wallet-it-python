<!doctype html>
<html <?php language_attributes(); ?>>
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge; <?php bloginfo('html_type') ?>; charset=<?php bloginfo('charset') ?>" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <?php if(get_option('custom-meta-keywords')!=""): ?>
    <meta name="keywords" content="<?php echo get_option('custom-meta-keywords'); ?>">
    <?php endif; ?>
    
    <?php if(get_option('custom-meta-description')!=""): ?>
    <meta name="description" content="<?php echo get_option('custom-meta-description'); ?>">
    <?php else: ?>
    <meta name="description" content="<?php echo get_bloginfo('description'); ?>">
    <?php endif; ?>

    <?php wp_head(); ?>
</head>

<body class="t-Pac">

<?php get_template_part('template-parts/section-cookies'); ?>
    
<div class="body_wrapper push_container clearfix" id="page_top">
    <div class="skiplink sr-only">
        <ul>
            <li>
                <a accesskey="2" href="#main_container"><?php echo __('Go to content','italiawp2'); ?></a>
            </li>
            <li>
                <a accesskey="3" href="#menup"><?php echo __('Go to the navigation menu','italiawp2'); ?></a>
            </li>
            <li><a accesskey="4" href="#footer"><?php echo __('Go to the footer','italiawp2'); ?></a></li>
        </ul>
    </div>
        
    <header id="mainheader" class="u-background-50">
    <?php get_template_part('menu'); ?>
    </header>

    <main id="main_container">
    
    <?php if (is_user_logged_in()):
        $user = wp_get_current_user();
        $spidRole_value = get_user_meta($user->ID, 'spidRole', true);
    ?>
    <div class="site-content" style="border: 1px solid black; padding: 1em;">
            <h2>Benvenuto <span style="color: blue;"><?php echo $user->first_name.' '.$user->last_name; ?></span></h2>
            <p>Di seguito potrai trovare le tue informazioni principali:</p>
            <ul>
                <li><strong>Nome:</strong> <?php echo $user->first_name; ?></li>
                <li><strong>Cognome:</strong> <?php echo $user->last_name; ?></li>
                <li><strong>Codice fiscale:</strong> <?php echo $user->nickname; ?></li>
                <li><strong>Email:</strong> <?php echo $user->user_email; ?></li>
                <li><strong>Spid level:</strong> <?php echo $spidRole_value; ?></li>
            </ul>
        </div>
    <?php endif; ?>
            
    <?php if(!is_attachment()) italiawp2_create_breadcrumbs(); ?>
