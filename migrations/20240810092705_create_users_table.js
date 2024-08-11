exports.up = function(knex) {
    return knex.schema.createTable('b_users', function(table) {
        table.increments('id').primary();
        table.string('name');
        table.string('email').unique();
        table.string('password');
        table.string('credential_id');
        table.string('public_key');
        table.string('challenge');
        table.integer('counter').defaultTo(0);
        table.timestamps(true, true);
    });
};

exports.down = function(knex) {
    return knex.schema.dropTable('b_users');
};