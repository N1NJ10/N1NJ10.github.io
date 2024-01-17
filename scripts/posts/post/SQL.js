const newPost = {
    title: 'SQL 101',
    body: `
    <p>SQL is a programming language that deals with the different DBMSs to do things in databases</p>
    <p>SQL can be classified in a lot of ways but the most common one is: -</p>
    <p>Data Definition Language (DDL): Queries that create, modify objects in the database.</p>
    <p>Data Manipulation Language (DML): Queries that help us deal with managing and manipulating data in the database.</p>
    <p>Data Control Language (DCL): Queries that help us deal with controls, rights, and permission in the database system.</p>
    <p>Transaction Control Language (TCL): Queries used for managing and controlling the transactions in a database to maintain consistency. In this article we will focus on DDL and DML</p>
    <p>First of all, we should know some database concepts</p>
    <h3> You can find this post on my Medium from <a href="https://medium.com/@Fady_Moheb/sql101-780f745197f0"> here </a>
    `,
    description: 'Welcome N1NJ10 , this time we will not discuss about security stuff but about database stuff specific SQL server , I will try to talk about basics SQL 101',
    date: new Date(1901, 6, 2),
    previewPicture: '/pages/Photos/sql.png',
    tags: ['SQL'],
    author: 'N1NJ10',
    category: 'SQL'
};

export default newPost;