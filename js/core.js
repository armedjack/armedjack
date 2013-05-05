(function ($) {

/*pubsub*/
var o = $( {} );

$.subscribe = function() {
o.on.apply(o, arguments);
};

$.unsubscribe = function() {
o.off.apply(o, arguments);
};

$.publish = function() {
o.trigger.apply(o, arguments);
};

/*конец pubsub*/
/*ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ*/
/*определение мобильного пользователя*/
var isMobile = {
    Android: function() {
        return navigator.userAgent.match(/Android/i);
    },
    BlackBerry: function() {
        return navigator.userAgent.match(/BlackBerry/i);
    },
    iOS: function() {
        return navigator.userAgent.match(/iPhone|iPad|iPod/i);
    },
    Opera: function() {
        return navigator.userAgent.match(/Opera Mini/i);
    },
    Windows: function() {
        return navigator.userAgent.match(/IEMobile/i);
    },
    any: function() {
        return (isMobile.Android() || isMobile.BlackBerry() || isMobile.iOS() || isMobile.Opera() || isMobile.Windows());
    }
};

var mobile = isMobile.any();
/**************************************/
/*********плавный slidetoggle**********/
	var smooth = function (block) {

			var height = block.height();
					
			if ( block.hasClass('smooth-showed') ) {
				
			    block.animate({ height: 0, opacity: 0 }, { duration: 400, complete: function () {		
				block.height(height);		     		      
			  	block.removeClass('smooth-showed').addClass('smooth-hidden');} 
			    });
			  } else {
			  		
			  		block.height(0);			  		
			  		block.addClass('smooth-showed').removeClass('smooth-hidden');
			    	block.show().animate({ height : height, opacity: 1 }, { duration: 400});
			    			    		 		
				};

		};
/**************************************/


/*КОНЕЦ ВСПОМОГАТЕЛЬНЫХ*/

$('html').addClass('js');
/*добавление формы дочернего комментария (ответа на комментарий)*/


var replyForm = { /*Объект - форма ответа на коммент*/	

	f : $('#com-answ').html(),   /*загружаем шаблон формы в переменную*/		
	init: function () {
		$.subscribe ('com-answer/click', replyForm.toggle);
		$.subscribe ('data/submited', replyForm.throwData);	
		$.subscribe ('data/throwed', replyForm.addReplyToPage);			
		$(document).on('click', function(event){ 			
    		if ($(event.target).hasClass('com-answer')) { /*клик по ссылке "Ответить" под комментарием*/
	    		
	    		event.preventDefault();	    		
	    		$.publish('com-answer/click', event.target);
	    		/*авторазворот ветки если нужно*/	    			    		
	    		col_btn = $(event.target).siblings('div.col-btn'); //находим кнопку свертки комментов	    		
	    		replies = $(event.target).parents('div.com-msg').siblings('div.com-replies'); //находим ветку ответов	    			    		
	    		if (col_btn.length && replies.css('opacity') == '0') { $.publish('expand', col_btn); } //если ее нашли, то публикуем триггер для разворота дочерних	    			    	
	    	}

		});
	    $('.com-answer_form_last').on('submit', function (event){/*аякс для формы комментирования поста*/
	    	event.preventDefault();	    	
	    	post_id = $('div.blog-post').attr('id');	    	
	    	args = {submitedForm:this, post_id:post_id};
	    	ancestors = undefined;	    	
    		$.publish('data/submited', args);
    		

	    }) 
	},

	toggle: function (e, comment){
		
		var $this = $(comment),		
			$thisParents = $this.parents('div.comment') //вся ветка вышестоящих комментариев
			$thisParentComment = $thisParents.filter(':first') //непосредственный предок
			$ParentCommentId = $thisParentComment.attr('id')//id родительского коммента,
     	   	openedForm = $('.com-answer_form'),
     		openedParentId = ''; //id коммента с октрытой формой     		
    	if (openedForm.length) {/*если существует открытая форма ответа на коммент*/
    		openedParentId = openedForm.parents('div.comment:first').attr('id'); //запоминаем родителя открытой формы	    		
    		openedForm.remove();
    	}
    	
    	if (!openedForm.length || $ParentCommentId  != openedParentId) {
    		//***переписываем id  всех комментариев-предков**********************    		
    		ancestors = [];
    		$.each($thisParents, function(index, value) { 	    		
				ancestors[index] = $(value).attr('id');				
			});//****************************************************************
			ancestors.reverse();//т.к. шли снизу вверх, нужно развернуть массив что бы на сервере правильно обработалось.	    					
    		$(replyForm.f).insertAfter($this.parents('div.com-msg:first'))
    					 // .attr('action', new_action)	    					  
    					  .submit(function (event) {
    					  		event.preventDefault();
    					  		post_id = $('div.blog-post').attr('id');
    					  		args = {submitedForm:this, post_id:post_id, ancestors:ancestors};			  		
    					  		$.publish('data/submited', args);
    					  		
    					  });    	
    	}
	},

	throwData: function(e, args){     		
		for (val in args) {window[val] = args[val];}		
		if (typeof ancestors === 'undefined'){ancestors = ''; parent_id = '';}
		console.log(ancestors);
		$submitedForm = $(submitedForm);				
		$.ajax ({
			type: 'POST',
			url:'/ajx/addreply/'+post_id,
			data: $submitedForm.serialize()+'&ancestors='+ancestors,
			success: function (data) {				
				args = {reply:data, parent_id: ancestors[ancestors.length-1], post_id:post_id};
				$.publish('data/throwed', args);
				if (ancestors!='') {$submitedForm.remove();	}//если не было предков, значит комментарий ответ на пост а не на другие комментарии, значит он был отправлен через нижнюю форму ответа и убирать ее не надо.
					else {							
						$submitedForm.find('textarea').val('');}
			}
		});
		
	},

	addReplyToPage: function (e, args) {			
		for (val in args) {window[val] = args[val];}
		t = $(reply);				
		//t.css('display', 'none');
		//if (ancestors) {console.log(ancestors);}
		
		if (ancestors == '') {			
			t.appendTo(".com-replies :first");
		}

		else {
			replies_div = $("div.comment#"+parent_id+" > div :last"); //ищем куда вставлять комментарий						
			t.prependTo(replies_div);			 
			t.parents('div.collapse').find('.col-btn').text(parseInt(t.parents('div.collapse').find('.col-btn').text())+1);
		}

		//t.slideDown();
		smooth(t);
		$('div#comments-count').text(parseInt($('div#comments-count').text())+1);			

		
	}

}


/*конец формы дочернего комментария (ответа на комментарий)*/   



/*кнопка свертки ветвей комментариев*/
var collapseBtn = {
	tmpl: $('#col_btn').html(),   /*загружаем шаблон кнопки*/
	init: function(){
		nodes = $('div.collapse');

		$.each(nodes, function(){			
			reply_href = $(this).children('div.com-msg').children('.com-answer');			
			$(collapseBtn.tmpl).insertAfter(reply_href)
								.text($(this).find('div.comment').length);

		});

		$.subscribe ('expand', collapseBtn.toggle);
		
		$(document).on('click', function(event){ 
	
    		if ($(event.target).hasClass('col-btn')) {
	    		event.preventDefault();		    		    		
	    		collapseBtn.toggle(event, event.target);
	    		reply_href = $(event.target).siblings('.com-answer'); //находим ветку ответов
	    		form = $(event.target).parent().siblings('form.com-answer_form');
	    		if (form.length) {$.publish('com-answer/click', reply_href);} 
	    	
	    	}
		});
						
	},

	toggle: function (e, btn) {		
		$btn = $(btn);			
		block = $btn.parent().siblings('.com-replies :first');
		

	
		smooth(block);
		/*block.slideToggle(400);*/
		$btn.toggleClass('expanded');

	}
}

/*конец свертки комментариев*/

/*создание поста(эффекты формы, кнопка вызова формы)*/

var postForm = {

	config: {
		qp_text1: '<a href="#" class="button-type-1"><span>Новый пост</span></a>',
		//qp_text2: '<a href="#" class="button-type-1 type-1-1"><span>Отмена</span></a>'
	},

	init: function(config){
		$.extend (this.config, config);		
		qp = $('div.quickpost');

		qp.html(postForm.config.qp_text1)		
			.prependTo($('body'))
			.on('click', this.showhide);

		$('div.close-btn').on('click', $.proxy (this.showhide, qp));
	},

	showhide: function(){
		var config = postForm.config,
			container = $('div.form_container');			
		$this = $(this);									
		$this.toggleClass('clicked'); 
		container.toggle();
		

		if (container.find('input#button').length) return;

		$('<input></input>',{
			type: 'submit',
			id: 'button',
			class: 'button-type-2',
			value: 'Опубликовать'

		})
			.appendTo($('.form_container form'))
			.on('click', function(event){
				
				if ($('input:first').val()=='' || $('form textarea').val()=='') {	
					event.preventDefault();
					$('p.error').text ('Необходим заголовок и текст. И то и другое!')
								.css('display','block');
				}

			});
			
	}	
}

/* BACK TO TOP*/
var topLink = $('#top-link');
$(window).scroll( function() {
	
	if($(window).scrollTop() > 0)
		topLink.stop(true, true).fadeIn(300);
	else
		topLink.stop(true, true).fadeOut(300);
});

topLink.click( function() {
	if (!mobile) {$('html, body').stop().animate({scrollTop:0}, 400);}
		else {$('html, body').stop().scrollTop(0);}
	return false;
});
/*****************/


if ($('body').hasClass('goodwood')) {	
	postForm.init();
	replyForm.init();	
}

collapseBtn.init();


})(jQuery);	