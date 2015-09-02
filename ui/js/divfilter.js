// Useful for debugging
function listProperties(obj) {
   var propList = "";
   for(var propName in obj) {
      if(typeof(obj[propName]) != "undefined") {
         propList += (propName + "=" + obj[propName] + ", ");
      }
   }
   window.alert(propList);
}

$(function() {
    'use strict';

    var DivFilter = (function(Arr) {
        var _input;

        function _onInputEvent(e) {
            _input = e.target;
            var divs = document.getElementById("providers");
            var providerdivs = divs.getElementsByTagName("div");

            for(var i=0; i < providerdivs.length; i++) {
                var anchor = providerdivs[i].getElementsByTagName("a");
                var x = _filter(anchor[0]);
                if (x == 0) {
                    providerdivs[i].style.display = 'none';
                    //$(providerdivs[i]).slideUp();
                } else {
                    providerdivs[i].style.display = 'inline';
                    //$(providerdivs[i]).slideDown();
                }
            };
        }

        function _filter(anchor) {
             var name = anchor.name.toLowerCase();
             var desc = $(anchor).data("original-title");
             var val = _input.value.toLowerCase();

             if (desc === "None") {
                 desc="";
             } else {
                 desc = desc.toLowerCase();
             }

             if (name.indexOf(val) === -1 && desc.indexOf(val) === -1) {
                 return 0;
             } else {
                 return 1;
             }
        }

        return {
            init: function() {
                var inputs = document.getElementsByClassName('div-filter');
                Arr.forEach.call(inputs, function(input) {
                    input.oninput = _onInputEvent;
                });
        }
    };
})(Array.prototype);

document.addEventListener('readystatechange', function() {
    if (document.readyState === 'complete') {
        DivFilter.init();
    }
});

});
