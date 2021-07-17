$('.btn btn-success').click(function() {
  var clone = $('.form-main').clone('.btn btn-success');
  $('.form-main').append(clone);
  });