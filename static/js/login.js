$(function () {
  'use strict';

  var $wrap  = $('#boxy-login-wrapper');
  var form   = document.forms['boxy-login-form'];
  var $inner = $(form).find('.boxy-form-inner');
  var $alert = $('#login-alert');

  // Tooltips Bootstrap 3
  $wrap.tooltip({
    placement: 'top',
    selector: '[data-toggle=tooltip]',
    trigger: 'hover',
    delay: { show: 250, hide: 150 }
  });

  // Utilidad: mostrar/ocultar alerta
  function showAlert(msg) {
    if (!msg) { $alert.stop(true, true).fadeOut(150); return; }
    $alert.text(msg).stop(true, true).fadeIn(150);
    $wrap.addClass('shake');
    setTimeout(function(){ $wrap.removeClass('shake'); }, 500);
  }

  // Tapa izquierda → empezar (quita giro inicial)
  $wrap.on('click', '.end-cap.left .glyphicon-user', function (e) {
    e.preventDefault();
    $inner.removeClass('rotateFirst3d');
    $('#boxy-input').focus();
  });

  // Paso 1: Usuario → validar y rotar a contraseña
  function goToPassword() {
    var user = form['username'];
    if (!user.value.trim()) {
      user.placeholder = 'Introduce tu usuario';
      showAlert('Por favor, introduce tu usuario.');
    } else {
      showAlert(null);
      $inner.addClass('rotated90');
      $('#boxy-password').focus();
    }
  }
  $wrap.on('click', '.side.front .boxy-button', function (e) {
    e.preventDefault();
    goToPassword();
  });

  // Paso 2: Contraseña → enviar formulario
  function submitForm() {
    var pass = form['password'];
    if (!pass.value.trim()) {
      pass.placeholder = 'Introduce tu contraseña';
      showAlert('Por favor, introduce tu contraseña.');
    } else {
      showAlert(null);
      form.submit();
    }
  }
  $wrap.on('click', '.side.bottom .boxy-final-button', function (e) {
    e.preventDefault();
    submitForm();
  });

  // ⌨️ Tab o Enter → avanzar
  $inner.on('keydown', '#boxy-input, #boxy-password', function (e) {
    var key = e.keyCode || e.which;
    if (key === 9 || key === 13) { // Tab o Enter
      e.preventDefault();
      if (this.id === 'boxy-input') {
        goToPassword();
      } else if (this.id === 'boxy-password') {
        submitForm();
      }
    }
  });

  // Icono de la cara → focus en su input
  $wrap.on('click', '.side .glyphicon', function (e) {
    e.preventDefault();
    var $inp = $(this).parent().find('input');
    if ($inp.length) $inp.focus();
  });
});
