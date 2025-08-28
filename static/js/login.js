$(function () {
  'use strict';

  var _boxyWrap = document.getElementById('boxy-login-wrapper');
  var _boxyLoginForm = document.forms['boxy-login-form'];
  var _boxyFormInner = $(_boxyLoginForm).find('div.boxy-form-inner');
  var _boxySide = $(_boxyFormInner).find('span.side');

  var _boxyInput;
  var _boxyPassword;
  var _boxyEmail;

  var _boxyButton = [
    $(_boxySide[0]).find('button.boxy-button').attr('data-step', '0'),
    $(_boxySide[1]).find('button.boxy-button').attr('data-step', '1'),
    $(_boxySide[2]).find('button.boxy-button').attr('data-step', '2'),
    $(_boxySide[2]).find('input[name=remember-me]'),
    $(_boxySide[2]).find('label[for=remember-me]'),
    $(_boxySide[3]).find('button.boxy-button').attr('data-step', '9')
  ];

  var _boxyEndCaps = $(_boxyFormInner).find('span.end-cap');
  var _boxyLeftCap = $(_boxyEndCaps[0]);
  var _boxyRightCap = $(_boxyEndCaps[1]);

  var _toLogin = _boxyLeftCap.find('.glyphicon-user');
  var _boxyMessage = $(_boxyWrap).find('em.small-forgot');
  var _rememberMeOp = $('input#remember-me');

  var _checked = $(_boxyWrap).find('span.boxy-checked'),
    _unchecked = $(_boxyWrap).find('span.boxy-unchecked'),
    _boxyRefreshButton = $(_boxyWrap).find('.boxy-refresh'),
    _boxyForgot = $(_boxyWrap).find('.boxy-forgot');

  var _toolTipOps = {
    placement: 'top',
    'data-html': true,
    'data-animation': true,
    selector: '[data-toggle=tooltip]',
    trigger: 'hover',
    delay: { show: 250, hide: 150 }
  };

  // Inits Bootstrap Tooltips
  $(_boxyWrap).tooltip(_toolTipOps);

  // Handles "Remember me" checkbox icons
  $(_rememberMeOp).on('change', function () {
    if ($(this).is(':checked')) {
      _checked.css('display', 'block');
      _unchecked.css('display', 'none');
    } else {
      _checked.css('display', 'none');
      _unchecked.css('display', 'block');
    }
    return false;
  });

  // Sets focus on next available input field
  $(_boxyFormInner).on('keydown', '#boxy-input , #boxy-password', function (evt) {
    var keyCode = evt.keyCode || evt.which;
    if (keyCode == 9) {
      evt.preventDefault();
      $(this).next('button').click();
      $(this).parent().next('.side').find('input').focus();
    }
  });

  _toLogin.on('click', function (evt) {
    $(_boxyFormInner).removeClass('rotateFirst3d');
    $(this).next('.side').find('input').focus();
    evt.preventDefault();
    return false;
  });

  // Next -- Username field
  $(_boxyButton[0]).on('click', function (evt) {
    evt.preventDefault();
    _boxyInput = document.forms['boxy-login-form']['username'];
    if (!_boxyInput.value) {
      $(_boxyWrap).addClass('shake');
      _boxyMessage.fadeIn('slow');
      _boxyInput.placeholder = 'enter your username to continue';
    } else {
      $(_boxyLoginForm).find('.boxy-form-inner').addClass('rotated90');
      _boxyMessage.fadeOut('slow');
    }
  });

  // Next -- Password field
  $(_boxyButton[1]).on('click', function (evt) {
    evt.preventDefault();
    _boxyPassword = document.forms['boxy-login-form']['password'];
    if (!_boxyPassword.value) {
      $(_boxyWrap).addClass('shake');
      _boxyMessage.fadeIn('slow');
      _boxyPassword.placeholder = 'enter your password to continue';
    } else {
      $(_boxyLoginForm).find('.boxy-form-inner').addClass('rotated180');
      _boxyMessage.fadeOut('slow');
    }
  });

  // OK button -- ahora envía el formulario a Flask
  $(_boxyButton[2]).on('click', function (evt) {
    evt.preventDefault();
    _boxyLoginForm.submit();
  });

  // Forgot
  $(_boxyButton[5]).on('click', function (evt) {
    evt.preventDefault();
    _boxyEmail = document.forms['boxy-login-form']['email'];
    if (!_boxyEmail.value) {
      $(_boxyWrap).addClass('shake');
      _boxyEmail.placeholder = 'enter your email for instructions';
    } else {
      $(_boxyFormInner).addClass('rotatedBack90');
      _boxyMessage.fadeOut('slow');
      _boxyRefreshButton.click();
    }
  });

  // Refresh
  $(_boxyRefreshButton).on('click', function (evt) {
    var _usernameInput = document.getElementsByName('username')[0];
    var _passwordInput = document.getElementsByName('password')[0];
    var _emailInput = document.getElementsByName('email')[0];

    _boxyEndCaps.removeClass('boxy-failure').removeClass('boxy-success');
    $(this).addClass('animate-refresh');

    _usernameInput.placeholder = 'username';
    _passwordInput.placeholder = 'password';
    _emailInput.placeholder = 'email';

    _usernameInput.value = '';
    _passwordInput.value = '';
    _emailInput.value = '';

    $(_boxyFormInner).removeClass('rotated90 rotated180 rotatedBack90 rotatedBack180 rotate3d');
    $(_boxyWrap).removeClass('shake');

    _boxyMessage.fadeOut('slow');
    _boxyRefreshButton.fadeOut('slow');

    var _disableInputs = $(_boxyFormInner).find('input');
    _disableInputs.removeAttr('disabled');

    evt.preventDefault();
  });

  // Forgot link
  $(_boxyForgot).on('click', function (evt) {
    evt.preventDefault();
    _boxyMessage.fadeOut('slow');
    _boxyRefreshButton.fadeOut('slow');
    $(_boxyFormInner).addClass('rotatedBack90');
  });

  // Click en iconos para focus en input
  $('.glyphicon-user, .glyphicon-asterisk, .glyphicon-question-sign').on('click', function (evt) {
    evt.preventDefault();
    var _setFocusInput = $(this).parent().find('input');
    return _setFocusInput.focus();
  });
});
