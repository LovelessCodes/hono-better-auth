# 🔥 Hono x Better Auth
Welcome to the **Hono x Better Auth** project.   
This project combines the power of Hono, Better Auth, and Drizzle ORM to provide a robust and scalable authentication solution.

## Using
![Hono Version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgithub.com%2FLovelessCodes%2Fhono-better-auth%2Fraw%2Fmaster%2Fpackage.json&query=%24.dependencies.hono&style=for-the-badge&logo=hono&label=hono&color=E36002)    
![Better Auth Version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgithub.com%2FLovelessCodes%2Fhono-better-auth%2Fraw%2Fmaster%2Fpackage.json&query=%24.dependencies.better-auth&style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0nNjAnIGhlaWdodD0nNDUnIHZpZXdCb3g9JzAgMCA2MCA0NScgY2xhc3M9J3ctNSBoLTUnIHhtbG5zPSdodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Zyc+PHBhdGggZmlsbC1ydWxlPSdldmVub2RkJyBjbGlwLXJ1bGU9J2V2ZW5vZGQnIGQ9J00wIDBIMTVWMTVIMzBWMzBIMTVWNDVIMFYzMFYxNVYwWk00NSAzMFYxNUgzMFYwSDQ1SDYwVjE1VjMwVjQ1SDQ1SDMwVjMwSDQ1WicgZmlsbD0nd2hpdGUnPjwvcGF0aD48L3N2Zz4=&label=better-auth&color=2B2D3E)   
![Drizzle Version](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgithub.com%2FLovelessCodes%2Fhono-better-auth%2Fraw%2Fmaster%2Fpackage.json&query=%24.dependencies.drizzle-orm&style=for-the-badge&logo=drizzle&label=drizzle&color=C5F74F)

## Installation

**Optional**: 
```sh
bunx gitpick LovelessCodes/hono-better-auth.git
```

Follow these steps to set up and run the project:

1. **Install Dependencies**:
    Use the following command to install the project dependencies:

    ```sh
    bun install
    ```

2. **Configure Environment Variables**:
    Copy the `.env.example` file to `.env` and configure the environment variables according to your needs.

3. **Run Migrations**:
    Run the migrations with the command:

    ```sh
    bunx drizzle-kit push
    ```

4. **Run the Application**:
    Start the development server with the command:

    ```sh
    bun run dev
    ```

5. **Access the Application**:
    Open your web browser and navigate to [http://localhost:8558](http://localhost:8558) to access the application.

## About

- **Hono**: A next-generation Node.js framework that provides a comprehensive ecosystem to build fast and reliable web applications.
  
- **Better Auth**: A flexible and easy-to-use authentication library that ensures secure user authorization.

- **Drizzle ORM**: A lightweight and efficient ORM for TypeScript-based projects, providing seamless database interactions.

We hope you enjoy using Hono x Better Auth. If you have any questions, feel free to reach out through [GitHub Issues](https://github.com/LovelessCodes/hono-better-auth/issues).