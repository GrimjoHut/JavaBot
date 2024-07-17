<!DOCTYPE html>
<html>
<head>
    <title> BUYSELL</title>
</head>
<body>
<h1>BUYSELL</h1><hr>
<h4>Товары со всей России</h4>
<#list products as product>
    <div>
        <p><b>${product.title}</b> ${product.price} руб | <a href="/product/${product.id}">Подробнее...</a></p>
    </div>
</#list>
<hr>
<h3>Cоздать новый товар</h3>
<form action="/product/create" method="post">
    Название товара: <input type="text" name="title"/><br><br>
    Описание товара: <input type="text" name="description"/><br><br>
    Цена товара: <input type="number" name="price"/><br><br>
    Город: <input type="text" name="city"/><br><br>
    Имя: <input type="text" name="author"/><br><br>
    <input type="submit" value="Добавить товар"/>
</form>
</body>
</html>
