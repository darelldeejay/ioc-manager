$(function () {
  'use strict';

  var $wrap = $('#boxy-login-wrapper');
  var form = document.forms['boxy-login-form'];
  var $inner = $(form).find('.boxy-form-inner');

  // Tooltips Bootstrap 3
  $wrap.tooltip({
    placement: 'top',
    selector: '[data-toggle=tooltip]',
    trigger: 'hover',
    delay: { show: 250, hide: 150 }
  });

  // Al hacer click en el icono de la tapa izquierda, empezamos (quita el giro inicial)
  $wrap.on('click', '.end-cap.left .glyphicon-user', function (e) {
    e.preventDefault();
    $inner.removeClass('rotateFirst3d');
    $('#boxy-input').focus();
  });

  // Paso 1: Usuario → validar y rotar a contraseña
  $wrap.on('click', '.side.front .boxy-button', function (e) {
    e.preventDefault();
    var user = form['username'];
    if (!user.value.trim()) {
      $wrap.addClass('shake');
      user.placeholder = 'Introduce tu usuario';
      setTimeout(function(){ $wrap.removeClass('shake'); }, 500);
    } else {
      $inner.addClass('rotated90');
      $('#boxy-password').focus();
    }
  });

  // Paso 2: Contraseña → enviar formulario
  // (el botón ya es type="submit", añadimos validación suave por si acaso)
  $wrap.on('click', '.side.bottom .boxy-final-button', function (e) {
    var pass = form['password'];
    if (!pass.value.trim()) {
      e.preventDefault();
      $wrap.addClass('shake');
      pass.placeholder = 'Introduce tu contraseña';
      setTimeout(function(){ $wrap.removeClass('shake'); }, 500);
    }
  });

  // Tab → avanzar
  $inner.on('keydown', '#boxy-input, #boxy-password', function (e) {
    var key = e.keyCode || e.which;
    if (key === 9) { // Tab
      e.preventDefault();
      $(this).next('button').trigger('click');
    }
  });

  // Click en el icono de cada cara → enfocar su input
  $wrap.on('click', '.side .glyphicon', function (e) {
    e.preventDefault();
    var $inp = $(this).parent().find('input');
    if ($inp.length) $inp.focus();
  });
});
